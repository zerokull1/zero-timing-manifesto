#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

struct learned_rule {
    uint16_t offset;
    uint16_t min_len;
    uint64_t mask;
    uint64_t pattern;
    uint32_t hits;
} __attribute__((packed));

static int bpf_obj_get(const char *path) {
    union bpf_attr attr = { .pathname = (uint64_t)(uintptr_t)path };
    return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_map_update(int fd, const void *key, const void *val) {
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)(uintptr_t)key,
        .value = (uint64_t)(uintptr_t)val,
        .flags = BPF_ANY
    };
    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_map_lookup(int fd, const void *key, void *val) {
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)(uintptr_t)key,
        .value = (uint64_t)(uintptr_t)val
    };
    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int rules_fd = bpf_obj_get("/sys/fs/bpf/swar_rules_map");
    int stats_fd = bpf_obj_get("/sys/fs/bpf/xdp_stats_map");
    if (rules_fd < 0 || stats_fd < 0) { perror("bpf_obj_get"); return 1; }

    char cmd = **(argv + 1);
    if (cmd == 'l' && argc >= 3) {
        FILE *f = fopen(*(argv + 2), "rb");
        if (!f) { perror("fopen"); return 1; }
        struct learned_rule r;
        uint32_t idx = 0;
        while (idx < 16 && fread(&r, sizeof(r), 1, f) == 1) {
            r.hits = 0;
            if (bpf_map_update(rules_fd, &idx, &r) < 0) perror("bpf_map_update");
            idx++;
        }
        fclose(f);
        printf("[HOT-INJECT] В ядерный XDP загружено %u SWAR-правил (%zu байт) без перезапуска!\n",
               idx, (size_t)idx * sizeof(r));
    } else if (cmd == 's') {
        uint32_t k0 = 0, k1 = 1;
        uint64_t pass_cnt = 0, drop_cnt = 0;
        bpf_map_lookup(stats_fd, &k0, &pass_cnt);
        bpf_map_lookup(stats_fd, &k1, &drop_cnt);
        printf("[KERNEL XDP STATS] XDP_PASS: %llu | XDP_DROP (отбито в ядре): %llu\n",
               (unsigned long long)pass_cnt, (unsigned long long)drop_cnt);
    }
    close(rules_fd);
    close(stats_fd);
    return 0;
}
