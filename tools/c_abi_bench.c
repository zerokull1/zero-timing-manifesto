// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

extern void     zero_cisco_init(void);
extern uint32_t zero_cisco_inspect_frame(const uint8_t *frame_ptr, size_t frame_len);

extern void     zero_hft_init(uint32_t target_security_id);
extern int64_t  zero_hft_on_market_frame(const uint8_t *frame_ptr, size_t frame_len, uint64_t *out_price, uint32_t *out_qty);

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void) {
    const uint64_t ITERS = 10000000ULL;

    /* 1. Валидный Ethernet + IPv4 + TCP + TLS 1.3 ClientHello (108 байт) для Cisco DAQ */
    uint8_t tls_frame[] = {
        0x00,0x11,0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,0xaa,0xbb, 0x08,0x00,
        0x45,0x00, 0x00,0x5e, 0x00,0x01, 0x00,0x00, 0x40,0x06, 0x00,0x00,
        0x0a,0x00,0x00,0x02, 0x0a,0x00,0x00,0x01,
        0xd4,0x31, 0x01,0xbb, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x01,
        0x50,0x18, 0xff,0xff, 0x00,0x00, 0x00,0x00,
        0x16,0x03,0x01, 0x00,0x31, 0x01, 0x00,0x00,0x2d, 0x03,0x03,
        0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,
        0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,
        0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12,0x12
    };

    zero_cisco_init();
    uint64_t acc_daq = 0;
    for (int i = 0; i < 100000; i++) acc_daq += zero_cisco_inspect_frame(tls_frame, sizeof(tls_frame));

    uint64_t t0 = now_ns();
    for (uint64_t i = 0; i < ITERS; i++) {
        tls_frame[65] = (uint8_t)i;
        acc_daq += zero_cisco_inspect_frame(tls_frame, sizeof(tls_frame));
    }
    uint64_t t1 = now_ns();
    double daq_ns = (double)(t1 - t0) / (double)ITERS;
    double daq_mpps = ((double)ITERS / ((double)(t1 - t0) / 1e9)) / 1e6;

    /* 2. Биржевой UDP SBE/ITCH пакет (14 Eth + 20 IPv4 + 8 UDP + 48 SBE = 90 байт) для HFT Bridge */
    uint8_t hft_frame[] = {
        0x01,0x00,0x5e,0x00,0x00,0x01, 0x66,0x77,0x88,0x99,0xaa,0xbb, 0x08,0x00,
        0x45,0x00, 0x00,0x4c, 0x00,0x01, 0x00,0x00, 0x40,0x11, 0x00,0x00,
        0x0a,0x00,0x00,0x02, 0xef,0x00,0x00,0x01,
        0x27,0x10, 0x27,0x11, 0x00,0x38, 0x00,0x00,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
    };
    uint32_t sec_id = 1001;
    memcpy(hft_frame + 42 + 8, &sec_id, sizeof(sec_id));

    zero_hft_init(1001);
    uint64_t out_price = 0;
    uint32_t out_qty = 0;
    int64_t acc_hft = 0;
    for (int i = 0; i < 100000; i++) {
        acc_hft += zero_hft_on_market_frame(hft_frame, sizeof(hft_frame), &out_price, &out_qty);
    }

    uint64_t t2 = now_ns();
    for (uint64_t i = 0; i < ITERS; i++) {
        uint32_t seq = (uint32_t)(i + 1);
        memcpy(hft_frame + 42, &seq, sizeof(seq));
        acc_hft += zero_hft_on_market_frame(hft_frame, sizeof(hft_frame), &out_price, &out_qty);
    }
    uint64_t t3 = now_ns();
    double hft_ns = (double)(t3 - t2) / (double)ITERS;
    double hft_mpps = ((double)ITERS / ((double)(t3 - t2) / 1e9)) / 1e6;

    printf("==============================================================\n");
    printf(" NATIVE C-ABI DUAL-PLUGIN BENCHMARK (10,000,000 pkts, 1 Core)\n");
    printf("==============================================================\n");
    printf(" Cisco DAQ L7 Shield : %6.2f ns/pkt | %6.2f Mpps (chk=%llu)\n", daq_ns, daq_mpps, (unsigned long long)acc_daq);
    printf(" HFT SBE/ITCH Bridge : %6.2f ns/pkt | %6.2f Mpps (chk=%lld)\n", hft_ns, hft_mpps, (long long)acc_hft);
    printf("==============================================================\n");
    return 0;
}
