#ifndef ZERO_MODULE_ABI_H
#define ZERO_MODULE_ABI_H

#include <stdint.h>
#include <stddef.h>

#define ZEROMANI_MODULE_MAGIC 0x494E414D4F52455AULL // "ZEROMANI"
#define ZERO_MODULE_ABI_VER   1

typedef struct {
    uint64_t magic;
    uint32_t abi_version;
    uint32_t module_id;
    const char *name;
    int (*init)(uint64_t seed);
    size_t (*process_frame)(uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns);
    void (*shutdown)(void);
} zero_module_descriptor_t;

#endif
