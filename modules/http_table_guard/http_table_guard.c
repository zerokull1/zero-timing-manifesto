#include "../module_abi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_HTTP_SIGS 64

typedef struct __attribute__((packed)) {
    uint64_t sig_hash;
    uint32_t kind;
    uint32_t hits;
} http_sig_t;

static http_sig_t *http_db = NULL;
static size_t http_count = 0;

static inline uint64_t fnv1a_64(const uint8_t *p, size_t n) {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint64_t)(*(p + i));
        h *= 0x100000001B3ULL;
    }
    return h;
}

static inline int has_token(const uint8_t *buf, size_t len, const char *tok, size_t tlen) {
    if (len < tlen) return 0;
    for (size_t i = 0; i + tlen <= len; i++) {
        if (memcmp(buf + i, tok, tlen) == 0) return 1;
    }
    return 0;
}

static uint32_t classify_http_anomaly(const uint8_t *payload, size_t plen) {
    if (has_token(payload, plen, "Content-Length:", 15) &&
        has_token(payload, plen, "Transfer-Encoding:", 18)) return 1;
    if (has_token(payload, plen, "<script", 7) || has_token(payload, plen, "javascript:", 11)) return 2;
    if (plen > 24 && *(payload + 0) == 0x82 && *(payload + 1) == 0x82) return 3;
    return 0;
}

static int http_init(uint64_t seed) {
    (void)seed;
    if (!http_db) http_db = calloc(MAX_HTTP_SIGS, sizeof(http_sig_t));
    http_count = 0;
    return http_db ? 0 : -1;
}

int http_load_db(const char *path, size_t *out_count) {
    FILE *f = fopen(path, "rb");
    if (!f) { if (out_count) *out_count = 0; return -1; }
    uint64_t hdr = 0;
    if (fread(&hdr, 8, 1, f) != 1 || hdr != ZEROMANI_MODULE_MAGIC) { fclose(f); return -2; }
    if (!http_db) http_db = calloc(MAX_HTTP_SIGS, sizeof(http_sig_t));
    http_count = 0;
    http_sig_t s;
    while (http_count < MAX_HTTP_SIGS && fread(&s, sizeof(s), 1, f) == 1) {
        *(http_db + http_count) = s;
        http_count++;
    }
    fclose(f);
    if (out_count) *out_count = http_count;
    return 0;
}

int http_save_db(const char *path) {
    if (!http_db) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    uint64_t hdr = ZEROMANI_MODULE_MAGIC;
    fwrite(&hdr, 8, 1, f);
    for (size_t i = 0; i < http_count; i++) fwrite(http_db + i, sizeof(http_sig_t), 1, f);
    fclose(f);
    return 0;
}

int http_learn_attack(const uint8_t *buf, size_t len) {
    if (!http_db || !buf || len <= 54) return 0;
    const uint8_t *payload = buf + 54;
    size_t plen = len - 54;
    uint32_t kind = classify_http_anomaly(payload, plen);
    if (kind == 0) return 0;
    uint64_t sig = fnv1a_64(payload, plen);
    for (size_t i = 0; i < http_count; i++) {
        if ((http_db + i)->sig_hash == sig) return 0;
    }
    if (http_count < MAX_HTTP_SIGS) {
        (http_db + http_count)->sig_hash = sig;
        (http_db + http_count)->kind = kind;
        (http_db + http_count)->hits = 1;
        http_count++;
        return 1;
    }
    return 0;
}

static size_t http_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns) {
    (void)max_cap;
    if (out_delay_ns) *out_delay_ns = 0;
    if (!http_db || !buf || len <= 54 || http_count == 0) return 0;
    uint64_t sig = fnv1a_64(buf + 54, len - 54);
    for (size_t i = 0; i < http_count; i++) {
        if ((http_db + i)->sig_hash == sig) { (http_db + i)->hits++; return 1; }
    }
    return 0;
}

static void http_shutdown(void) {
    if (http_db) { memset(http_db, 0, MAX_HTTP_SIGS * sizeof(http_sig_t)); free(http_db); http_db = NULL; }
    http_count = 0;
}

const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC, .abi_version = ZERO_MODULE_ABI_VER, .module_id = 4,
    .name = "adaptive_http_table_guard", .init = http_init,
    .process_frame = http_process_frame, .shutdown = http_shutdown
};
