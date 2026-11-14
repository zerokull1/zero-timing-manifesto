#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

struct mutagen_config {
    uint32_t active;
    uint32_t pad;
    uint64_t seed;
    uint64_t tx_mutated;
    uint64_t rx_restored;
};

static int bpf_obj_get(const char *path) {
    union bpf_attr attr = { .pathname = (uint64_t)(uintptr_t)path };
    return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_map_lookup(int fd, const void *key, void *val) {
    union bpf_attr attr = { .map_fd = fd, .key = (uint64_t)(uintptr_t)key, .value = (uint64_t)(uintptr_t)val };
    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int bpf_map_update(int fd, const void *key, const void *val) {
    union bpf_attr attr = { .map_fd = fd, .key = (uint64_t)(uintptr_t)key, .value = (uint64_t)(uintptr_t)val, .flags = BPF_ANY };
    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    const char *pin = getenv("MUTAGEN_PIN") ? getenv("MUTAGEN_PIN") : "/sys/fs/bpf/mutagen_cfg";
    int fd = bpf_obj_get(pin);
    if (fd < 0) { perror("bpf_obj_get"); return 1; }

    uint32_t k = 0;
    struct mutagen_config cfg = {0};
    bpf_map_lookup(fd, &k, &cfg);

    if (strcmp(argv[1], "on") == 0) {
        cfg.active = 1;
        cfg.seed = (argc >= 3) ? strtoull(argv[2], NULL, 16) : 0x9E3779B97F4A7C15ULL;
        bpf_map_update(fd, &k, &cfg);
        printf("[MUTAGEN ON]  Канал активирован | Seed: 0x%016llx\n", (unsigned long long)cfg.seed);
    } else if (strcmp(argv[1], "off") == 0) {
        cfg.active = 0;
        bpf_map_update(fd, &k, &cfg);
        printf("[MUTAGEN OFF] Штатный режим (обычный прозрачный трафик)\n");
    } else if (strcmp(argv[1], "status") == 0) {
        printf("Режим: %s | Seed: 0x%016llx | TX Mutated: %llu | RX Restored: %llu\n",
               cfg.active ? "ACTIVE (MUTATED WIRE)" : "BYPASS (NORMAL TRAFFIC)",
               (unsigned long long)cfg.seed,
               (unsigned long long)cfg.tx_mutated,
               (unsigned long long)cfg.rx_restored);
    }
    close(fd);
    return 0;
}
