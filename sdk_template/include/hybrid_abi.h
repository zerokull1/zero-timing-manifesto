#ifndef HYBRID_ABI_H
#define HYBRID_ABI_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void asm_stream_write_32(void *dst_aligned32, const void *src_aligned32);
uint64_t asm_hw_entropy_u64(void);
uint32_t rust_core_process(const uint8_t *buf, size_t len);
#ifdef __cplusplus
}
#endif
#endif
