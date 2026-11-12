#ifndef ZERO_TIMING_H
#define ZERO_TIMING_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZERORING_MAGIC 0x5A45524F52494E47ULL /* "ZERORING" */
#define ZERORING_VERDICT_PASS 1
#define ZERORING_VERDICT_DROP 0

/* Выровненный по 64 байтам слот кольцевого буфера (без False Sharing) */
typedef struct __attribute__((aligned(64))) {
    uint64_t tsc_timestamp;
    uint64_t iat_cycles;
    uint32_t flow_hash;
    uint16_t payload_len;
    uint8_t  l7_proto;
    uint8_t  verdict;
    uint8_t  reserved[40];
} ZeroRingSlot;

/* Заголовок разделяемой памяти /dev/shm/ZERORING */
typedef struct __attribute__((aligned(64))) {
    uint64_t magic;
    uint32_t version;
    uint32_t capacity;
    uint64_t write_idx;
    uint64_t drop_count;
    uint8_t  reserved[32];
} ZeroRingHeader;

/* C-ABI точки входа для Cisco DAQ / Snort 3 и HFT SBE/ITCH мостов */
int32_t zero_daq_inspect_frame(const uint8_t *frame_ptr, size_t frame_len);
int64_t zero_hft_parse_sbe_header(const uint8_t *msg_ptr, size_t msg_len);

#ifdef __cplusplus
}
#endif

#endif /* ZERO_TIMING_H */
