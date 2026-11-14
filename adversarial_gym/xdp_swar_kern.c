#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct learned_rule {
    __u16 offset;
    __u16 min_len;
    __u64 mask;
    __u64 pattern;
    __u32 hits;
} __attribute__((packed));

#define MAX_XDP_RULES 16

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_XDP_RULES);
    __type(key, __u32);
    __type(value, struct learned_rule);
} swar_rules_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2); // [0] = XDP_PASS, [1] = XDP_DROP
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats_map SEC(".maps");

SEC("xdp")
int xdp_swar_shield(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = (__u64)(data_end - data);

    #pragma unroll
    for (__u32 i = 0; i < MAX_XDP_RULES; i++) {
        __u32 idx = i;
        struct learned_rule *r = bpf_map_lookup_elem(&swar_rules_map, &idx);
        if (!r || r->mask == 0) continue;

        __u32 off = r->offset;
        if (off > 128) continue;
        if (pkt_len < r->min_len) continue;

        __u8 *ptr = (__u8 *)data + off;
        if ((void *)(ptr + 8) > data_end) continue;

        __u64 word = 0;
        __builtin_memcpy(&word, ptr, 8);
        if ((word & r->mask) == r->pattern) {
            __sync_fetch_and_add(&r->hits, 1);
            __u32 drop_k = 1;
            __u64 *drops = bpf_map_lookup_elem(&xdp_stats_map, &drop_k);
            if (drops) __sync_fetch_and_add(drops, 1);
            return XDP_DROP;
        }
    }

    __u32 pass_k = 0;
    __u64 *passes = bpf_map_lookup_elem(&xdp_stats_map, &pass_k);
    if (passes) __sync_fetch_and_add(passes, 1);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
