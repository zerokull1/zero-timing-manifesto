// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define MODE_FAIL_OPEN 0
#define MODE_MONITOR   1
#define MODE_ENFORCE   2

#define EVENT_TTL_ANOMALY 1
#define EVENT_RATE_FLOOD  2
#define EVENT_TCP_SCAN    3

#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

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
    __type(value, __u8);
} blacklist_v4 SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 16);
} events_ring SEC(".maps");

static __always_inline void emit_alert(__u64 now, __u32 src_ip, __u32 reason) {
    struct alert_event *e = bpf_ringbuf_reserve(&events_ring, sizeof(*e), 0);
    if (!e) return;
    e->timestamp_ns = now;
    e->src_ip = src_ip;
    e->reason = reason;
    bpf_ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);
}

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

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

    __u16 h_proto = eth->h_proto;
    void *nh = (void *)(eth + 1);

    // Разбор до 2 вложенных тегов VLAN (802.1Q / 802.1ad QinQ)
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
            struct vlan_hdr *vh = nh;
            if ((void *)(vh + 1) > data_end) return XDP_PASS;
            h_proto = vh->h_vlan_encapsulated_proto;
            nh = (void *)(vh + 1);
        }
    }

    if (h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = nh;
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->ihl < 5) return XDP_DROP;

    __u32 src_ip = ip->saddr;

    // 1. Белый список (доверенные хосты)
    if (bpf_map_lookup_elem(&whitelist_v4, &src_ip)) {
        if (stats) stats->whitelisted_packets++;
        return XDP_PASS;
    }

    // 2. Мгновенный чёрный список (blacklist_v4)
    if (bpf_map_lookup_elem(&blacklist_v4, &src_ip)) {
        if (stats) stats->dropped_packets++;
        if (mode == MODE_ENFORCE) return XDP_DROP;
    }

    __u64 now = bpf_ktime_get_ns();

    // 3. Проверка аномальных TCP-сканеров (NULL, XMAS, SYN+FIN)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            __u8 flags = ((__u8 *)tcp)[13];
            __u8 is_null = (flags == 0);
            __u8 is_xmas = ((flags & 0x29) == 0x29); // FIN + PSH + URG
            __u8 is_syn_fin = ((flags & 0x03) == 0x03); // SYN + FIN
            if (is_null || is_xmas || is_syn_fin) {
                if (stats) stats->dropped_packets++;
                emit_alert(now, src_ip, EVENT_TCP_SCAN);
                if (mode == MODE_ENFORCE) return XDP_DROP;
            }
        }
    }

    // 4. Защита от флуда по частоте пакетов (LRU Rate-Limit)
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

    // 5. Проверка TTL-сигнатур тетеринга (65 / 129)
    __u8 ttl = ip->ttl;
    __u32 block_65  = cfg ? cfg->block_ttl_65  : 1;
    __u32 block_129 = cfg ? cfg->block_ttl_129 : 1;

    if ((block_65 && ttl == 65) || (block_129 && ttl == 129)) {
        if (stats) stats->dropped_packets++;
        emit_alert(now, src_ip, EVENT_TTL_ANOMALY);
        if (mode == MODE_ENFORCE) return XDP_DROP;
    }

    // Если на этой очереди RX подключён пользовательский AF_XDP сокет — отдаём пакет в Zero-Copy UMEM
    __u32 qid = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_map, &qid)) {
        return bpf_redirect_map(&xsks_map, qid, 0);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
