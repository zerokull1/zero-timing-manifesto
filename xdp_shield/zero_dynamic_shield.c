#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

#define MODE_FAIL_OPEN 0
#define MODE_MONITOR   1
#define MODE_ENFORCE   2

#define EVENT_TTL_ANOMALY 1
#define EVENT_RATE_FLOOD  2

struct shield_cfg {
    __u32 mode;
    __u32 block_ttl_65;
    __u32 block_ttl_129;
    __u32 pps_limit;
};

struct rate_state {
    __u64 window_start_ns;
    __u32 count;
};

struct datarec {
    __u64 rx_packets;
    __u64 dropped_packets;
    __u64 whitelisted_packets;
};

struct alert_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 reason;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} whitelist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_state);
} rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct shield_cfg);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct datarec);
} stats_map SEC(".maps");

// Кольцевой буфер для пробуждения AI-агента по прерыванию (0% CPU в простое)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 16);
} events_ring SEC(".maps");

static __u64 last_alert_ns = 0;

static __always_inline void emit_alert(__u64 now, __u32 src_ip, __u32 reason) {
    // Анти-спам: будим AI не чаще 1 раза в 500 мс (500,000,000 нс)
    if (now - last_alert_ns < 500000000ULL) return;
    last_alert_ns = now;

    struct alert_event *e = bpf_ringbuf_reserve(&events_ring, sizeof(*e), 0);
    if (!e) return;
    e->timestamp_ns = now;
    e->src_ip = src_ip;
    e->reason = reason;
    bpf_ringbuf_submit(e, 0);
}

SEC("xdp")
int zero_dynamic_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    __u32 zero = 0;
    struct datarec *stats = bpf_map_lookup_elem(&stats_map, &zero);
    if (stats) stats->rx_packets++;

    struct shield_cfg *cfg = bpf_map_lookup_elem(&config_map, &zero);
    __u32 mode = cfg ? cfg->mode : MODE_ENFORCE;
    if (mode == MODE_FAIL_OPEN) return XDP_PASS;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 src_ip = ip->saddr;
    if (bpf_map_lookup_elem(&whitelist_v4, &src_ip)) {
        if (stats) stats->whitelisted_packets++;
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    __u32 limit = cfg ? cfg->pps_limit : 0;
    if (limit > 0) {
        struct rate_state *rs = bpf_map_lookup_elem(&rate_map, &src_ip);
        if (!rs) {
            struct rate_state init = { .window_start_ns = now, .count = 1 };
            bpf_map_update_elem(&rate_map, &src_ip, &init, BPF_ANY);
        } else {
            if (now - rs->window_start_ns >= 1000000000ULL) {
                rs->window_start_ns = now;
                rs->count = 1;
            } else {
                rs->count++;
                if (rs->count > limit) {
                    if (stats) stats->dropped_packets++;
                    emit_alert(now, src_ip, EVENT_RATE_FLOOD);
                    if (mode == MODE_ENFORCE) return XDP_DROP;
                }
            }
        }
    }

    __u8 ttl = ip->ttl;
    __u32 block_65  = cfg ? cfg->block_ttl_65  : 1;
    __u32 block_129 = cfg ? cfg->block_ttl_129 : 1;

    if ((block_65 && ttl == 65) || (block_129 && ttl == 129)) {
        if (stats) stats->dropped_packets++;
        emit_alert(now, src_ip, EVENT_TTL_ANOMALY);
        if (mode == MODE_ENFORCE) return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
