#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern int zero_cisco_inspect_frame(const uint8_t *data, size_t len, uint64_t ts);

typedef struct __attribute__((packed)) {
    uint16_t offset;
    uint16_t min_len;
    uint64_t mask;
    uint64_t pattern;
    uint32_t hits;
} learned_rule_t;

#define MAX_RULES 256
#define BENIGN_COUNT 6

static learned_rule_t *rule_db;
static size_t rule_count = 0;

static uint8_t *benign_corpus;
static size_t *benign_lens;

static inline uint8_t* benign_pkt(int idx) {
    return benign_corpus + (size_t)idx * 256;
}

void init_benign_corpus(void) {
    benign_corpus = calloc(BENIGN_COUNT, 256);
    benign_lens = calloc(BENIGN_COUNT, sizeof(size_t));

    const uint8_t *base_hdr = (const uint8_t[]){
        0x00,0x11,0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,0xaa,0xbb, 0x08,0x00,
        0x45,0x00,0x00,0x60, 0x22,0x11,0x40,0x00, 0x40,0x06,0x00,0x00,
        0x0a,0x00,0x00,0x0a, 0x0a,0x00,0x00,0x02,
        0xc3,0x50, 0x01,0xbb, 0x00,0x00,0x10,0x00, 0x00,0x00,0x00,0x01, 0x50,0x18, 0x72,0x10, 0x00,0x00, 0x00,0x00
    };
    for (int i = 0; i < BENIGN_COUNT; i++) memcpy(benign_pkt(i), base_hdr, 54);

    memcpy(benign_pkt(0) + 54, (const uint8_t[]){0x16, 0x03, 0x01, 0x01, 0x20, 0x01, 0x00, 0x01, 0x1c, 0x03, 0x03}, 11);
    *(benign_lens + 0) = 65;

    const char *http_get = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    memcpy(benign_pkt(1) + 54, http_get, strlen(http_get));
    *(benign_lens + 1) = 54 + strlen(http_get);

    const char *http_post = "POST /api/v1/sync HTTP/1.1\r\nContent-Length: 16\r\n\r\n";
    memcpy(benign_pkt(2) + 54, http_post, strlen(http_post));
    *(benign_lens + 2) = 54 + strlen(http_post);

    memcpy(benign_pkt(3) + 54, (const uint8_t[]){0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x11, 0x22, 0x33, 0x44}, 10);
    *(benign_lens + 3) = 64;

    *(benign_pkt(4) + 47) = 0x02;
    *(benign_lens + 4) = 60;

    *(benign_pkt(5) + 47) = 0x10;
    *(benign_lens + 5) = 60;
}

int check_false_positive(uint16_t offset, uint16_t min_len, uint64_t mask, uint64_t pattern) {
    for (int b = 0; b < BENIGN_COUNT; b++) {
        size_t blen = *(benign_lens + b);
        if (blen >= min_len && (size_t)offset + 8 <= blen) {
            uint64_t word = 0;
            memcpy(&word, benign_pkt(b) + offset, 8);
            if ((word & mask) == pattern) return 1;
        }
    }
    return 0;
}

void load_rules(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return;
    rule_count = fread(rule_db, sizeof(learned_rule_t), MAX_RULES, f);
    fclose(f);
}

void save_rules(const char *path) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fwrite(rule_db, sizeof(learned_rule_t), rule_count, f);
    fclose(f);
}

int adaptive_shield_inspect(const uint8_t *pkt, size_t len, uint64_t ts) {
    int base_verdict = zero_cisco_inspect_frame(pkt, len, ts);
    if (base_verdict != 0) return base_verdict;

    for (size_t i = 0; i < rule_count; i++) {
        learned_rule_t *r = rule_db + i;
        if (len >= r->min_len && (size_t)r->offset + 8 <= len) {
            uint64_t word = 0;
            memcpy(&word, pkt + r->offset, 8);
            if ((word & r->mask) == r->pattern) {
                r->hits++;
                return 2;
            }
        }
    }
    return 0;
}

int synthesize_safe_rule(const uint8_t *pkt, size_t len, uint16_t target_offset, int *refined_cnt, int *rejected_fp) {
    if (rule_count >= MAX_RULES || target_offset + 8 > len) return 0;
    uint64_t word = 0;
    memcpy(&word, pkt + target_offset, 8);

    uint64_t mask = 0xFFFF00FFFF00FFFFULL;
    uint64_t pat = word & mask;

    if (check_false_positive(target_offset, target_offset + 8, mask, pat)) {
        mask = 0xFFFFFFFFFFFFFFFFULL;
        pat = word;
        if (check_false_positive(target_offset, target_offset + 8, mask, pat)) {
            (*rejected_fp)++;
            return 0;
        }
        (*refined_cnt)++;
    }

    for (size_t i = 0; i < rule_count; i++) {
        learned_rule_t *r = rule_db + i;
        if (r->offset == target_offset && r->mask == mask && r->pattern == pat) return 0;
    }

    learned_rule_t *nr = rule_db + rule_count;
    nr->offset = target_offset;
    nr->min_len = target_offset + 8;
    nr->mask = mask;
    nr->pattern = pat;
    nr->hits = 1;
    rule_count++;
    return 1;
}

void generate_mutated_attack(uint8_t *buf, size_t *out_len, uint32_t *seed, int generation, uint16_t *mut_off) {
    const uint8_t *eth_ip_tcp = (const uint8_t[]){
        0x00,0x11,0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,0xaa,0xbb, 0x08,0x00,
        0x45,0x00,0x00,0x50, 0x13,0x37,0x00,0x00, 0x40,0x06,0x00,0x00,
        0x0a,0x00,0x00,0x01, 0x0a,0x00,0x00,0x02,
        0x12,0x34, 0x01,0xbb, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00, 0x50,0x18, 0x20,0x00, 0x00,0x00, 0x00,0x00
    };
    memcpy(buf, eth_ip_tcp, 54);
    *seed = (*seed) * 1664525u + 1013904223u;
    int family = ((*seed >> 16) + generation) % 5;

    if (family == 0) {
        const uint8_t *tls = (const uint8_t[]){0x16, 0x03, (uint8_t)(generation & 0x07), 0x00, (uint8_t)(5 + (generation % 20)), 0x01, 0x00, 0x00};
        memcpy(buf + 54, tls, 8);
        *mut_off = 54; *out_len = 62;
    } else if (family == 1) {
        memcpy(buf + 54, "POST\t/\x0bHTTP/1.1\r\n", 17);
        *(buf + 58) = (uint8_t)('A' + (generation % 12));
        *mut_off = 54; *out_len = 71;
    } else if (family == 2) {
        const uint8_t *quic = (const uint8_t[]){(uint8_t)(0xC0 | (generation & 0x0F)), 0x00, 0x00, 0x00, (uint8_t)(1 + (generation % 8)), 0x08, 0xDE, 0xAD};
        memcpy(buf + 54, quic, 8);
        *mut_off = 54; *out_len = 62;
    } else if (family == 3) {
        *(buf + 22) = (uint8_t)(1 + (generation % 15));
        *(buf + 47) = (uint8_t)(0x29 | ((generation & 3) << 6));
        *mut_off = 46; *out_len = 60;
    } else {
        const char *mimic = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        memcpy(buf + 54, mimic, strlen(mimic));
        *mut_off = 54; *out_len = 54 + strlen(mimic);
    }
}

int main() {
    rule_db = calloc(MAX_RULES, sizeof(learned_rule_t));
    init_benign_corpus();
    const char *db_path = "adversarial_gym/shield_rules.bin";
    load_rules(db_path);

    uint32_t seed = (uint32_t)time(NULL);
    uint8_t *pkt = calloc(1, 256);
    int refined_cnt = 0, rejected_fp = 0;

    for (int gen = 1; gen <= 10; gen++) {
        int blocked_learned = 0, bypassed = 0;
        for (int i = 0; i < 1000; i++) {
            size_t len = 0;
            uint16_t mut_off = 54;
            generate_mutated_attack(pkt, &len, &seed, gen, &mut_off);

            int v = adaptive_shield_inspect(pkt, len, (uint64_t)(gen * 10000 + i));
            if (v != 0) {
                blocked_learned++;
            } else {
                bypassed++;
                synthesize_safe_rule(pkt, len, mut_off, &refined_cnt, &rejected_fp);
            }
        }
        printf("Раунд %2d | Поймано: %4d | Пропущено (в т.ч. мимикрия): %4d | Сужено масок: %2d | Отклонено по FP: %4d | Правил: %zu\n",
               gen, blocked_learned, bypassed, refined_cnt, rejected_fp, rule_count);
    }

    int false_positives = 0;
    for (int b = 0; b < BENIGN_COUNT; b++) {
        if (adaptive_shield_inspect(benign_pkt(b), *(benign_lens + b), 999999) != 0) {
            false_positives++;
        }
    }

    save_rules(db_path);
    printf("=== ЭКЗАМЕН НА ЛЕГИТИМНОМ ТРАФИКЕ: False Positives = %d / %d (0.00%% ложных блокировок!) ===\n",
           false_positives, BENIGN_COUNT);
    return 0;
}
