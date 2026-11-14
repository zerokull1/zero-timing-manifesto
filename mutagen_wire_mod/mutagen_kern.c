#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct mutagen_config {
    __u32 active;
    __u32 redirect_ifindex;
    __u64 seed;
    __u64 tx_mutated;
    __u64 rx_restored;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mutagen_config);
} mutagen_cfg SEC(".maps");

static __always_inline __u64 derive_stream_key(__u64 seed, __u32 saddr, __u32 daddr, __u16 ip_id) {
    __u64 k = seed ^ (((__u64)saddr << 32) | (__u64)daddr);
    k ^= ((__u64)ip_id * 0x9e3779b97f4a7c15ULL);
    k ^= (k >> 33);
    k *= 0xff51afd7ed558ccdULL;
    k ^= (k >> 33);
    return k;
}

static __always_inline void apply_mutagen(struct xdp_md *ctx, struct mutagen_config *cfg, int is_egress) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return;
    if (iph->ihl != 5 || iph->protocol != IPPROTO_UDP) return;

    struct udphdr *udph = (void *)(iph + 1);
    if ((void *)(udph + 1) > data_end) return;
    if (is_egress) udph->check = 0;

    __u8 *payload = (__u8 *)(udph + 1);
    __u64 key = derive_stream_key(cfg->seed, iph->saddr, iph->daddr, iph->id);

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        __u64 *chunk = (__u64 *)(payload + i * 8);
        if ((void *)(chunk + 1) > data_end) break;
        *chunk ^= key;
        key = (key << 7) | (key >> 57);
        key ^= 0x9e3779b97f4a7c15ULL;
    }

    if (is_egress)
        __sync_fetch_and_add(&cfg->tx_mutated, 1);
    else
        __sync_fetch_and_add(&cfg->rx_restored, 1);
}

// Выходной XDP-мутатор + аппаратный bpf_redirect в провод без bridge.ko
SEC("xdp")
int mutagen_tx(struct xdp_md *ctx) {
    __u32 idx = 0;
    struct mutagen_config *cfg = bpf_map_lookup_elem(&mutagen_cfg, &idx);
    if (!cfg) return XDP_PASS;
    if (cfg->active) apply_mutagen(ctx, cfg, 1);
    if (cfg->redirect_ifindex > 0) return bpf_redirect(cfg->redirect_ifindex, 0);
    return XDP_PASS;
}

// Входной XDP-демутатор на приёмной стойке
SEC("xdp")
int mutagen_rx(struct xdp_md *ctx) {
    __u32 idx = 0;
    struct mutagen_config *cfg = bpf_map_lookup_elem(&mutagen_cfg, &idx);
    if (!cfg) return XDP_PASS;
    if (cfg->active) apply_mutagen(ctx, cfg, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
