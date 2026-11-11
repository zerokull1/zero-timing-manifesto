#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct shield_stats {
    __u64 passed;
    __u64 dropped_null_tcp;
    __u64 dropped_l7_smuggling;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct shield_stats);
} stats_map SEC(".maps");

SEC("xdp")
int xdp_zero_shield_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    __u32 key = 0;
    struct shield_stats *st = bpf_map_lookup_elem(&stats_map, &key);
    if (!st) return XDP_PASS;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        st->passed++;
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) {
        st->passed++;
        return XDP_PASS;
    }

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_DROP;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    // 1. Блокада TCP Null-сегментов (все флаги равны 0x00)
    __u8 tcp_flags = ((__u8 *)tcp)[13];
    if (tcp_flags == 0x00) {
        st->dropped_null_tcp++;
        return XDP_DROP;
    }

    // 2. Проверка L7 SWAR (первые 16 байт TCP Payload на HTTP Smuggling "POST /" + "chunked\r")
    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len >= sizeof(struct tcphdr)) {
        __u8 *payload = (__u8 *)tcp + tcp_hdr_len;
        if ((void *)(payload + 16) <= data_end) {
            __u64 q0 = *(__u64 *)payload;
            __u64 q1 = *(__u64 *)(payload + 8);
            // "POST /" (6 байт = 0x00002f2054534f50ULL) и "chunked\r" (0x0d64656b6e756863ULL)
            if ((q0 & 0x0000FFFFFFFFFFFFULL) == 0x00002F2054534F50ULL && q1 == 0x0D64656B6E756863ULL) {
                st->dropped_l7_smuggling++;
                return XDP_DROP;
            }
        }
    }

    st->passed++;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
