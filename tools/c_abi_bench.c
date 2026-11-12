#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "../include/zero_timing.h"

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void) {
    /* Валидный Ethernet + IPv4 + TCP + TLS 1.3 ClientHello (108 байт) */
    uint8_t tls_frame[108] = {
        0x00,0x11,0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,0xaa,0xbb, 0x08,0x00,
        0x45,0x00, 0x00,0x5e, 0x00,0x01, 0x00,0x00, 0x40,0x06, 0x00,0x00,
        0x0a,0x00,0x00,0x02, 0x0a,0x00,0x00,0x01,
        0xd4,0x31, 0x01,0xbb, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x01,
        0x50,0x18, 0xff,0xff, 0x00,0x00, 0x00,0x00,
        0x16,0x03,0x01, 0x00,0x31, 0x01, 0x00,0x00,0x2d, 0x03,0x03
    };
    memset(tls_frame + 65, 0x12, sizeof(tls_frame) - 65);

    zero_cisco_init();

    /* Прогрев L1-кэша */
    uint64_t acc = 0;
    for (int i = 0; i < 100000; i++) {
        acc += zero_cisco_inspect_frame(tls_frame, sizeof(tls_frame));
    }

    const uint64_t ITERS = 10000000ULL;
    uint64_t t0 = now_ns();
    for (uint64_t i = 0; i < ITERS; i++) {
        tls_frame[65] = (uint8_t)i; /* лёгкая вариация байта без ветвлений */
        acc += zero_cisco_inspect_frame(tls_frame, sizeof(tls_frame));
    }
    uint64_t t1 = now_ns();

    double elapsed_sec = (double)(t1 - t0) / 1e9;
    double ns_per_pkt = (double)(t1 - t0) / (double)ITERS;
    double mpps = ((double)ITERS / elapsed_sec) / 1e6;

    printf("==============================================================\n");
    printf(" NATIVE C-ABI BENCHMARK (10,000,000 packets, Single Core)\n");
    printf("==============================================================\n");
    printf(" Total Wall Time   : %.4f s\n", elapsed_sec);
    printf(" Throughput        : %.2f Mpps (Single Core)\n", mpps);
    printf(" Amortized Latency : %.2f ns/pkt (checksum=%llu)\n", ns_per_pkt, (unsigned long long)acc);
    printf("==============================================================\n");
    return 0;
}
