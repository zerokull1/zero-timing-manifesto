#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

// Режимы работы фильтра (меняются на лету без перезагрузки)
#define MODE_FAIL_OPEN 0  // Пропускать всё (аварийный байпас)
#define MODE_MONITOR   1  // Только считать аномалии, не блокировать
#define MODE_ENFORCE   2  // Боевой режим: XDP_DROP при нарушении

struct shield_cfg {
    __u32 mode;
    __u32 block_ttl_65;   // 1 = блокировать TTL 65 (Linux/Android тетеринг)
    __u32 block_ttl_129;  // 1 = блокировать TTL 129 (Windows/iOS тетеринг)
};

struct datarec {
    __u64 rx_packets;
    __u64 dropped_packets;
    __u64 whitelisted_packets;
};

// 1. Динамический белый список IPv4 (добавление/удаление IP за O(1) без перекомпиляции)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // IPv4 адрес в сетевом порядке байт (big-endian)
    __type(value, __u8);  // 1 = доверенный узел
} whitelist_v4 SEC(".maps");

// 2. Горячая конфигурация (1 ячейка с ключом 0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct shield_cfg);
} config_map SEC(".maps");

// 3. Per-CPU счётчики статистики (ноль атомарных блокировок между ядрами)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct datarec);
} stats_map SEC(".maps");

SEC("xdp")
int zero_dynamic_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    __u32 zero = 0;
    struct datarec *stats = bpf_map_lookup_elem(&stats_map, &zero);
    if (stats) {
        stats->rx_packets++;
    }

    // Проверяем глобальный режим (Fail-Open срабатывает мгновенно)
    struct shield_cfg *cfg = bpf_map_lookup_elem(&config_map, &zero);
    __u32 mode = cfg ? cfg->mode : MODE_ENFORCE;
    if (mode == MODE_FAIL_OPEN) {
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Проверка IP отправителя в динамическом белом списке (O(1))
    __u32 src_ip = ip->saddr;
    if (bpf_map_lookup_elem(&whitelist_v4, &src_ip)) {
        if (stats) stats->whitelisted_packets++;
        return XDP_PASS;
    }

    // Проверка сигнатур тетеринга (TTL 65 / 129)
    __u8 ttl = ip->ttl;
    __u32 block_65  = cfg ? cfg->block_ttl_65  : 1;
    __u32 block_129 = cfg ? cfg->block_ttl_129 : 1;

    if ((block_65 && ttl == 65) || (block_129 && ttl == 129)) {
        if (stats) stats->dropped_packets++;
        if (mode == MODE_ENFORCE) {
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
