#ifndef SSL_VPN_ASM_FASTPATH_H
#define SSL_VPN_ASM_FASTPATH_H

#include <stdint.h>

static inline uint64_t asm_hw_crc64_pair(uint64_t w0, uint64_t w1, uint64_t seed) {
    uint64_t acc = seed;
    __asm__ __volatile__(
        "crc32q %1, %0\n\t"
        "crc32q %2, %0\n\t"
        : "+r"(acc)
        : "r"(w0), "r"(w1)
    );
    return acc;
}

static inline uint64_t asm_branchless_hijack_check(uint64_t slot_tok, uint64_t pkt_tok,
                                                   uint64_t slot_bind, uint64_t pkt_bind) {
    uint64_t hit = 0, one = 1, zero = 0;
    __asm__ __volatile__(
        "cmpq %2, %1\n\t"
        "cmoveq %4, %0\n\t"
        "cmpq %3, %5\n\t"
        "cmoveq %6, %0\n\t"
        : "+r"(hit)
        : "r"(slot_tok), "r"(pkt_tok), "r"(slot_bind), "r"(one), "r"(pkt_bind), "r"(zero)
        : "cc"
    );
    return hit;
}

#endif
