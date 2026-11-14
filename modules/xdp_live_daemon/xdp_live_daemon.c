#define _GNU_SOURCE
#include "../module_abi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

typedef struct __attribute__((packed)) {
    uint16_t offset;
    uint16_t min_len;
    uint64_t mask;
    uint64_t pattern;
    uint32_t hits;
} swar_rule_t;

static swar_rule_t *active_rules = NULL;
static size_t active_count = 0;

static int bpf_obj_get(const char *path) {
    union bpf_attr attr = { .pathname = (uint64_t)(uintptr_t)path };
    return (int)syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_map_update(int fd, const void *key, const void *val) {
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)(uintptr_t)key,
        .value = (uint64_t)(uintptr_t)val,
        .flags = BPF_ANY
    };
    return (int)syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

// Загружает подписанные правила ZEROMANI из файла и при наличии карты XDP заливает их в ядро
int guardian_sync_rules(const char *rules_path, const char *bpf_pin_path, size_t *out_loaded, int *out_kernel_synced) {
    FILE *f = fopen(rules_path, "rb");
    if (!f) return -1;

    uint64_t hdr = 0;
    if (fread(&hdr, 8, 1, f) != 1 || hdr != ZEROMANI_MODULE_MAGIC) {
        fclose(f);
        return -2; // неверная авторская подпись
    }

    if (!active_rules) active_rules = calloc(16, sizeof(swar_rule_t));
    active_count = 0;

    int map_fd = bpf_obj_get(bpf_pin_path);
    int synced = 0;

    swar_rule_t r;
    while (active_count < 16 && fread(&r, sizeof(r), 1, f) == 1) {
        r.hits = 0;
        *(active_rules + active_count) = r;
        if (map_fd >= 0) {
            uint32_t k = (uint32_t)active_count;
            if (bpf_map_update(map_fd, &k, &r) == 0) synced++;
        }
        active_count++;
    }
    if (map_fd >= 0) close(map_fd);
    fclose(f);

    if (out_loaded) *out_loaded = active_count;
    if (out_kernel_synced) *out_kernel_synced = synced;
    return 0;
}

static int guardian_init(uint64_t seed) {
    (void)seed;
    if (!active_rules) active_rules = calloc(16, sizeof(swar_rule_t));
    return active_rules ? 0 : -1;
}

// Проверяет кадр по активной базе SWAR-правил сторожа (возвращает 0 при пропуске, 1 при блокировке)
static size_t guardian_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns) {
    (void)max_cap;
    if (out_delay_ns) *out_delay_ns = 0;
    if (!buf || !active_rules) return 0;

    for (size_t i = 0; i < active_count; i++) {
        swar_rule_t *r = active_rules + i;
        if (r->mask != 0 && len >= r->min_len && (size_t)r->offset + 8 <= len) {
            uint64_t w = 0;
            memcpy(&w, buf + r->offset, 8);
            if ((w & r->mask) == r->pattern) {
                r->hits++;
                return 1; // заблокировано сторожем
            }
        }
    }
    return 0;
}

static void guardian_shutdown(void) {
    if (active_rules) {
        memset(active_rules, 0, 16 * sizeof(swar_rule_t));
        free(active_rules);
        active_rules = NULL;
    }
    active_count = 0;
}

const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC,
    .abi_version = ZERO_MODULE_ABI_VER,
    .module_id = 2,
    .name = "xdp_live_guardian",
    .init = guardian_init,
    .process_frame = guardian_process_frame,
    .shutdown = guardian_shutdown
};
