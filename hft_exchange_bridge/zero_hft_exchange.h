// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#ifndef ZERO_HFT_EXCHANGE_H
#define ZERO_HFT_EXCHANGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Биржевой вердикт Tick-to-Trade (в обход ядра ОС)
#define HFT_ACTION_IGNORE       0
#define HFT_ACTION_BUY_TRIGGER  1
#define HFT_ACTION_SELL_TRIGGER 2
#define HFT_ACTION_DROP_SPOOF   3

// Выровненная по кэш-линии (64 байта) структура котировки SBE / ITCH
typedef struct __attribute__((aligned(64))) {
    uint64_t exchange_ts_ns;
    uint32_t security_id;
    uint32_t msg_seq_num;
    int64_t  best_bid_price;  // Фиксированная точка (x10^8)
    uint64_t best_bid_qty;
    int64_t  best_ask_price;  // Фиксированная точка (x10^8)
    uint64_t best_ask_qty;
    uint64_t local_tsc_cycles;
} ZeroMarketTick;

// Инициализация биржевого шлюза и сброс счётчиков последовательности (Gap Detection)
void zero_hft_init(uint32_t target_security_id);

// Горячий путь Tick-to-Trade: разбор сырого UDP-кадра SBE/ITCH, проверка Gap/Spoofing и триггер ордера (~25-40 тактов)
uint32_t zero_hft_on_market_frame(
    const uint8_t *frame_ptr,
    size_t frame_len,
    int64_t max_buy_price,
    int64_t min_sell_price,
    ZeroMarketTick *out_tick
);

#ifdef __cplusplus
}
#endif

#endif // ZERO_HFT_EXCHANGE_H
