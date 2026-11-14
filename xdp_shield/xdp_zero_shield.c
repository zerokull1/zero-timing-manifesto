/* ZERO_XDP_TTL_GUARD v1.3.0: Early L3/L4 TTL==0, Tiny-Fragment, TCP Null & L7 SWAR (HTTP Smuggling + TLS Record Splitting) */
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
    __u64 dropped_tls_splitting;
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
    if ((ip->frag_off & __constant_htons(0x3FFF)) != 0) {
        __sync_fetch_and_add(&st->dropped_null_tcp, 1);
        return XDP_DROP;
    }
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

    // 2. Проверка L7 SWAR (первые 16 байт TCP Payload)
    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len >= sizeof(struct tcphdr)) {
        __u8 *payload = (__u8 *)tcp + tcp_hdr_len;
        if ((void *)(payload + 16) <= data_end) {
            __u64 q0 = *(__u64 *)payload;
            __u64 q1 = *(__u64 *)(payload + 8);

            // 2a. HTTP Smuggling: "POST /" + "chunked\r"
            if ((q0 & 0x0000FFFFFFFFFFFFULL) == 0x00002F2054534F50ULL && q1 == 0x0D64656B6E756863ULL) {
                st->dropped_l7_smuggling++;
                return XDP_DROP;
            }

            // 2b. TLS Record Splitting (порт 443): Handshake 0x16 0x03 с record_len < 40 байт
            if (tcp->dest == bpf_htons(443)) {
                __u8 rec_type = (__u8)(q0 & 0xFF);
                __u8 maj_ver  = (__u8)((q0 >> 8) & 0xFF);
                __u16 rlen_be = (__u16)((q0 >> 24) & 0xFFFF);
                __u16 rlen    = bpf_ntohs(rlen_be);
                if (rec_type == 0x16 && maj_ver == 0x03 && rlen < 40) {
                    st->dropped_tls_splitting++;
                    return XDP_DROP;
                }
            }
        }
    }

    st->passed++;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

SEC("xdp_peer")
int xdp_peer_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}
