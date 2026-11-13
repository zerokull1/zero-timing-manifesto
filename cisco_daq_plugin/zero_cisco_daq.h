// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#ifndef ZERO_CISCO_DAQ_H
#define ZERO_CISCO_DAQ_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Вердикты инспекции для Cisco DAQ / Fast-Path Pipeline
#define ZERO_VERDICT_PASS               0
#define ZERO_VERDICT_DROP_L3_L4_NULL    1
#define ZERO_VERDICT_DROP_L7_SMUGGLING  2
#define ZERO_VERDICT_DROP_L7_TLS_ANOM   3

typedef struct {
    uint64_t total_inspected;
    uint64_t dropped_l3_l4;
    uint64_t dropped_l7;
    uint64_t last_latency_cycles;
} ZeroCiscoStats;

// Инициализация безблокировочного контекста на выделенном ядре
void zero_cisco_init(void);

// Горячий путь инспекции сырого Ethernet-кадра (Zero-Copy, без аллокаций, 36-60 тактов)
uint32_t zero_cisco_inspect_frame(const uint8_t *frame_ptr, size_t frame_len);

// Получение атомарной телеметрии для Cisco DNA / Telemetry Collector
void zero_cisco_get_stats(ZeroCiscoStats *out_stats);

#ifdef __cplusplus
}
#endif

#endif // ZERO_CISCO_DAQ_H
