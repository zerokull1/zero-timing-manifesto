#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("classifier")
int tc_egress_mutagen(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    // Не трогаем локальный трафик
    if ((iph->daddr & bpf_htonl(0xFF000000)) == bpf_htonl(0x7F000000)) return TC_ACT_OK;

    __u32 rnd = bpf_get_prandom_u32();

    // 1. Мутация IPv4 Identification на выходе из сетевой карты с пересчётом контрольной суммы ядра
    __be16 old_id = iph->id;
    __be16 new_id = (__be16)(rnd & 0xFFFF);
    iph->id = new_id;
    bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), old_id, new_id, 2);

    // 2. Плавающий TTL (58..64) для маскировки отпечатка ОС на магистрали без поломки маршрутизации
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data; iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    if (iph->ttl >= 60) {
        __u8 old_ttl = iph->ttl;
        __u8 new_ttl = (__u8)(58 + ((rnd >> 16) & 0x06));
        __be16 old_w = bpf_htons(((__u16)old_ttl << 8) | iph->protocol);
        __be16 new_w = bpf_htons(((__u16)new_ttl << 8) | iph->protocol);
        iph->ttl = new_ttl;
        bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), old_w, new_w, 2);
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
