#include "../module_abi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TLS_PROFILES 64

typedef struct __attribute__((packed)) {
    uint64_t tls_fp;     // структурный отпечаток (версия + шифры + SNI)
    uint32_t sni_hash;   // хэш доменного имени SNI
    uint32_t seen_hits;
} tls_profile_t;

static tls_profile_t *tls_db = NULL;
static size_t tls_count = 0;

static inline uint64_t fnv1a_64(const uint8_t *p, size_t n) {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= (uint64_t)(*(p + i)); h *= 0x100000001B3ULL; }
    return h;
}

// Разбор TLS ClientHello (без расшифровки трафика): извлекает версию, отпечаток и аномалии фрагментации
static int parse_tls_client_hello(const uint8_t *pay, size_t plen, uint64_t *out_fp, int *out_is_attack) {
    *out_is_attack = 0;
    if (plen < 6 || *(pay + 0) != 0x16) return 0; // не TLS Handshake
    uint16_t rec_ver = (uint16_t)((*(pay + 1) << 8) | *(pay + 2));
    uint16_t rec_len = (uint16_t)((*(pay + 3) << 8) | *(pay + 4));
    // Атака 1: устаревший SSLv3/TLS 1.0 (0x0300..0x0301) или мелкая фрагментация ClientHello (< 40 байт)
    if (rec_ver < 0x0303 || rec_len < 40 || *(pay + 5) != 0x01) {
        *out_is_attack = 1;
        return 1;
    }
    size_t inspect_len = (plen > 160) ? 160 : plen;
    *out_fp = fnv1a_64(pay + 5, inspect_len - 5) ^ ((uint64_t)rec_ver << 48);
    return 1;
}

static int tls_init(uint64_t seed) {
    (void)seed;
    if (!tls_db) tls_db = calloc(MAX_TLS_PROFILES, sizeof(tls_profile_t));
    tls_count = 0;
    return tls_db ? 0 : -1;
}

int tls_load_db(const char *path, size_t *out_count) {
    FILE *f = fopen(path, "rb");
    if (!f) { if (out_count) *out_count = 0; return -1; }
    uint64_t hdr = 0;
    if (fread(&hdr, 8, 1, f) != 1 || hdr != ZEROMANI_MODULE_MAGIC) { fclose(f); return -2; }
    if (!tls_db) tls_db = calloc(MAX_TLS_PROFILES, sizeof(tls_profile_t));
    tls_count = 0;
    tls_profile_t p;
    while (tls_count < MAX_TLS_PROFILES && fread(&p, sizeof(p), 1, f) == 1) {
        *(tls_db + tls_count) = p;
        tls_count++;
    }
    fclose(f);
    if (out_count) *out_count = tls_count;
    return 0;
}

int tls_save_db(const char *path) {
    if (!tls_db) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    uint64_t hdr = ZEROMANI_MODULE_MAGIC;
    fwrite(&hdr, 8, 1, f);
    for (size_t i = 0; i < tls_count; i++) fwrite(tls_db + i, sizeof(tls_profile_t), 1, f);
    fclose(f);
    return 0;
}

int tls_learn_client(const uint8_t *buf, size_t len) {
    if (!tls_db || !buf || len <= 60) return 0;
    uint64_t fp = 0; int bad = 0;
    if (!parse_tls_client_hello(buf + 54, len - 54, &fp, &bad) || bad) return 0;
    for (size_t i = 0; i < tls_count; i++) {
        if ((tls_db + i)->tls_fp == fp) { (tls_db + i)->seen_hits++; return 0; }
    }
    if (tls_count < MAX_TLS_PROFILES) {
        (tls_db + tls_count)->tls_fp = fp;
        (tls_db + tls_count)->sni_hash = (uint32_t)(fp & 0xFFFFFFFFU);
        (tls_db + tls_count)->seen_hits = 1;
        tls_count++;
        return 1;
    }
    return 0;
}

static size_t tls_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns) {
    (void)max_cap;
    if (out_delay_ns) *out_delay_ns = 0;
    if (!tls_db || !buf || len <= 54) return 0;
    uint64_t fp = 0; int bad = 0;
    if (!parse_tls_client_hello(buf + 54, len - 54, &fp, &bad)) return 0;
    if (bad) return 1; // откат версии SSL/TLS или фрагментация ClientHello -> атака!
    if (tls_count == 0) return 0;
    for (size_t i = 0; i < tls_count; i++) {
        if ((tls_db + i)->tls_fp == fp) return 0; // доверенный отпечаток TLS + SNI
    }
    return 1; // неизвестный отпечаток бота / спуфинг SNI -> в тарпит!
}

static void tls_shutdown(void) {
    if (tls_db) { memset(tls_db, 0, MAX_TLS_PROFILES * sizeof(tls_profile_t)); free(tls_db); tls_db = NULL; }
    tls_count = 0;
}

const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC, .abi_version = ZERO_MODULE_ABI_VER, .module_id = 7,
    .name = "adaptive_https_tls_guard", .init = tls_init,
    .process_frame = tls_process_frame, .shutdown = tls_shutdown
};
