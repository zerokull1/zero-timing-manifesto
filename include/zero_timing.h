#ifndef ZERO_TIMING_H
#define ZERO_TIMING_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZERORING_MAGIC          0x5A45524F52494E47ULL /* "ZERORING" */
#define ZERORING_ABI_VERSION    0x00010100U           /* v1.1.0-beta */

/* Вердикты Inline Data-Plane */
#define ZERORING_VERDICT_DROP   0
#define ZERORING_VERDICT_PASS   1
#define ZERORING_VERDICT_TRAP   2 /* Deception Trap / Tarpit изоляция */
#define ZERORING_VERDICT_MUTATE 3 /* Moving Target Defense (MTD) ротация */

/* Битовые флаги политики активной защиты */
#define ZERO_DEFENSE_TRAP_ENABLE   (1U << 0)
#define ZERO_DEFENSE_MTD_ENABLE    (1U << 1)
#define ZERO_DEFENSE_STRICT_L7     (1U << 2)

/* Выровненный по 64 байтам слот кольцевого буфера (без False Sharing) */
typedef struct __attribute__((aligned(64))) {
    uint64_t tsc_timestamp;
    uint64_t iat_cycles;
    uint32_t flow_hash;
    uint16_t payload_len;
    uint8_t  l7_proto;
    uint8_t  verdict;
    uint32_t mtd_salt_id;
    uint8_t  reserved[36];
} ZeroRingSlot;

/* Заголовок разделяемой памяти /dev/shm/ZERORING (строго 64 байта) */
typedef struct __attribute__((aligned(64))) {
    uint64_t magic;
    uint32_t version;
    uint32_t capacity;
    uint64_t write_idx;
    uint64_t drop_count;
    uint64_t trap_count;            /* Счётчик пакетов, ушедших в ловушку/tarpit */
    uint32_t mtd_epoch;             /* Текущая эпоха ротации солей MTD */
    uint32_t defense_flags;         /* Битовая маска ZERO_DEFENSE_* */
    uint16_t entropy_threshold_x100;/* Порог энтропии Шеннона * 100 (напр. 750 = 7.50) */
    uint8_t  reserved[14];
} ZeroRingHeader;

/* C-ABI точки входа для Cisco DAQ / Snort 3, HFT мостов и Active Defense */
void     zero_cisco_init(void);
uint32_t zero_cisco_inspect_frame(const uint8_t *frame_ptr, size_t frame_len);
void     zero_hft_init(uint32_t target_security_id);
int64_t  zero_hft_on_market_frame(const uint8_t *frame_ptr, size_t frame_len);
void    zero_configure_active_defense(uint32_t flags, uint16_t entropy_threshold_x100, uint32_t mtd_epoch);

#ifdef __cplusplus
}
#endif

#endif /* ZERO_TIMING_H */
