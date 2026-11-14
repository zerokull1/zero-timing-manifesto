#include "../module_abi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_HTTP_RULES 32

typedef struct __attribute__((packed)) {
    uint64_t feature_mask;
    uint64_t feature_pattern;
    uint32_t hits;
} http_learned_rule_t;

static http_learned_rule_t *rules_db = NULL;
static size_t rules_count = 0;
static const char *db_file_path = "modules/http_table_guard/http_learned.zdb";

// Извлекает 64-битный структурный отпечаток HTTP/1.1 и таблицы заголовков HPACK за один проход
static uint64_t extract_http_features(const uint8_t *buf, size_t len) {
    if (len <= 54) return 0;
    const uint8_t *p = buf + 54;
    size_t plen = len - 54;

    uint32_t cl_count = 0;
    uint32_t te_count = 0;
    uint32_t host_count = 0;
    uint32_t hpack_dyn_refs = 0;
    uint32_t script_tags = 0;

    for (size_t i = 0; i < plen; i++) {
        uint8_t c = *(p + i);
        // Считаем динамические ссылки HPACK (старший бит 1 в префиксе заголовков HTTP/2)
        if ((c & 0x80) != 0) hpack_dyn_refs++;

        if (i + 15 <= plen && memcmp(p + i, "Content-Length:", 15) == 0) cl_count++;
        if (i + 18 <= plen && memcmp(p + i, "Transfer-Encoding:", 18) == 0) te_count++;
        if (i + 5  <= plen && memcmp(p + i, "Host:", 5) == 0) host_count++;
        if (i + 7  <= plen && (memcmp(p + i, "<script", 7) == 0 || memcmp(p + i, "<table", 6) == 0)) script_tags++;
    }

    uint64_t fp = 0;
    fp |= ((uint64_t)(cl_count & 0xF)) << 0;
    fp |= ((uint64_t)(te_count & 0xF)) << 4;
    fp |= ((uint64_t)(host_count & 0xF)) << 8;
    fp |= ((uint64_t)(hpack_dyn_refs > 32 ? 0xF : (hpack_dyn_refs >> 1))) << 12;
    fp |= ((uint64_t)(script_tags & 0xF)) << 16;
    // Флаг конфликта CL + TE (классический HTTP Request Smuggling)
    if (cl_count > 0 && te_count > 0) fp |= (1ULL << 20);
    // Флаг дублирования заголовков
    if (cl_count > 1 || te_count > 1 || host_count > 1) fp |= (1ULL << 21);
    return fp;
}

// Сохраняет выученные правила на диск с авторской подписью ZEROMANI
int http_guard_save_db(const char *path) {
    FILE *f = fopen(path ? path : db_file_path, "wb");
    if (!f) return -1;
    uint64_t magic = ZEROMANI_MODULE_MAGIC;
    uint32_t cnt = (uint32_t)rules_count;
    fwrite(&magic, 8, 1, f);
    fwrite(&cnt, 4, 1, f);
    if (cnt > 0) fwrite(rules_db, sizeof(http_learned_rule_t), cnt, f);
    fclose(f);
    return 0;
}

// Загружает ранее выученные правила с диска с проверкой авторской подписи ZEROMANI
int http_guard_load_db(const char *path) {
    FILE *f = fopen(path ? path : db_file_path, "rb");
    if (!f) return 0; // первый запуск, база пустая — бот начнёт учиться с нуля
    uint64_t magic = 0;
    uint32_t cnt = 0;
    if (fread(&magic, 8, 1, f) != 1 || magic != ZEROMANI_MODULE_MAGIC || fread(&cnt, 4, 1, f) != 1) {
        fclose(f);
        return -2;
    }
    if (cnt > MAX_HTTP_RULES) cnt = MAX_HTTP_RULES;
    if (cnt > 0) {
        rules_count = fread(rules_db, sizeof(http_learned_rule_t), cnt, f);
    }
    fclose(f);
    return (int)rules_count;
}

// Обучение модуля на пойманной аномалии с XOR-обобщением признаков (без ложных срабатываний)
int http_guard_learn(const uint8_t *bad_buf, size_t bad_len, const uint8_t *clean_buf, size_t clean_len) {
    if (!rules_db) return -1;
    uint64_t fp_bad = extract_http_features(bad_buf, bad_len);
    uint64_t fp_clean = clean_buf ? extract_http_features(clean_buf, clean_len) : 0;
    if (fp_bad == 0 || fp_bad == fp_clean) return 0;

    // Пробуем обобщить с уже существующим близким правилом
    for (size_t i = 0; i < rules_count; i++) {
        http_learned_rule_t *r = rules_db + i;
        uint64_t diff = (r->feature_pattern ^ fp_bad) & r->feature_mask;
        // Если различаются не больше 8 младших бит (вариации счётчиков), расширяем маску
        if ((diff & ~0xFFULL) == 0) {
            uint64_t candidate_mask = r->feature_mask & ~diff;
            uint64_t candidate_pat  = r->feature_pattern & candidate_mask;
            if ((fp_clean & candidate_mask) != candidate_pat) {
                r->feature_mask = candidate_mask;
                r->feature_pattern = candidate_pat;
                return 1;
            }
        }
    }

    if (rules_count < MAX_HTTP_RULES) {
        http_learned_rule_t *nr = rules_db + rules_count;
        nr->feature_mask = 0xFFFFFFFFFFFFFFFFULL;
        nr->feature_pattern = fp_bad;
        nr->hits = 1;
        rules_count++;
        return 1;
    }
    return 0;
}

size_t http_guard_rule_count(void) {
    return rules_count;
}

static int http_guard_init(uint64_t seed) {
    (void)seed;
    if (!rules_db) rules_db = calloc(MAX_HTTP_RULES, sizeof(http_learned_rule_t));
    rules_count = 0;
    http_guard_load_db(db_file_path);
    return rules_db ? 0 : -1;
}

static size_t http_guard_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns) {
    (void)max_cap;
    if (out_delay_ns) *out_delay_ns = 0;
    if (!buf || !rules_db || rules_count == 0) return 0;

    uint64_t fp = extract_http_features(buf, len);
    if (fp == 0) return 0;

    for (size_t i = 0; i < rules_count; i++) {
        http_learned_rule_t *r = rules_db + i;
        if ((fp & r->feature_mask) == r->feature_pattern) {
            r->hits++;
            return 1; // заблокировано по выученному правилу
        }
    }
    return 0;
}

static void http_guard_shutdown(void) {
    if (rules_db) {
        http_guard_save_db(db_file_path);
        memset(rules_db, 0, MAX_HTTP_RULES * sizeof(http_learned_rule_t));
        free(rules_db);
        rules_db = NULL;
    }
    rules_count = 0;
}

const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC,
    .abi_version = ZERO_MODULE_ABI_VER,
    .module_id = 4,
    .name = "adaptive_http_table_guard",
    .init = http_guard_init,
    .process_frame = http_guard_process_frame,
    .shutdown = http_guard_shutdown
};
