// SPDX-License-Identifier: GPL-3.0
// Zero-Timing ISP Anti-Tethering & Stateful Bypass XDP Shield (Single-File)
// Compile: clang -O2 -g -target bpf -c isp_ttl65_shield.c -o isp_ttl65_shield.o
// Attach:  ip link set dev <IFACE> xdpgeneric obj isp_ttl65_shield.o sec xdp

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Per-CPU drop counters (Lock-free telemetry)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

enum {
    STAT_PASS = 0,
    STAT_DROP_TTL_SPOOF = 1,
    STAT_DROP_NULL_TCP = 2,
    STAT_DROP_TINY_SPLIT = 3,
};

static __always_inline void inc_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&drop_stats, &idx);
    if (val) (*val)++;
}

SEC("xdp")
int zero_isp_shield(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 1. Ethernet Header Check
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. IPv4 Header & TTL Spoof / Anti-Tethering Check
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_DROP;

    // Native mobile stack starts at TTL=64 -> arrives at ISP gateway with TTL<=63.
    // Spoofed tethering (TTL=65) or Phase-2 desync jump (TTL=90) is blocked instantly.
    if (ip->ttl == 65 || ip->ttl == 90 || ip->ttl == 129) {
        inc_stat(STAT_DROP_TTL_SPOOF);
        return XDP_DROP;
    }

    if (ip->protocol != IPPROTO_TCP) {
        inc_stat(STAT_PASS);
        return XDP_PASS;
    }

    // 3. TCP Header & Stateful Bypass Mitigation
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
        return XDP_DROP;

    // Read raw TCP flags byte (offset 13 in TCP header)
    __u8 tcp_flags = *((__u8 *)tcp + 13);

    // Phase 3 Mitigation: Drop Null-TCP segments (0x00) trying to bypass Fast-Path
    if (tcp_flags == 0x00) {
        inc_stat(STAT_DROP_NULL_TCP);
        return XDP_DROP;
    }

    // Phase 2 Mitigation: Drop 1-byte session splitting with micro-window (Window <= 45)
    __u16 tot_len = bpf_ntohs(ip->tot_len);
    __u32 payload_len = tot_len - ip_hdr_len - tcp_hdr_len;
    __u16 win_size = bpf_ntohs(tcp->window);

    if (payload_len == 1 && win_size <= 45 && (tcp_flags & 0x08)) {
        inc_stat(STAT_DROP_TINY_SPLIT);
        return XDP_DROP;
    }

    inc_stat(STAT_PASS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
