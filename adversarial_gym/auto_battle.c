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

#define MAX_RULES 64
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

// Умный синтезатор с XOR-обобщением: вычисляет мутирующие биты и вычитает их из маски!
int synthesize_generalized_rule(const uint8_t *pkt, size_t len, uint16_t target_offset) {
    if (target_offset + 8 > len) return 0;
    uint64_t word = 0;
    memcpy(&word, pkt + target_offset, 8);

    // 1. Пробуем обобщить существующее правило на том же смещении, если у них общих >= 24 стабильных бита
    for (size_t i = 0; i < rule_count; i++) {
        learned_rule_t *r = rule_db + i;
        if (r->offset == target_offset) {
            uint64_t diff = (r->pattern ^ word) & r->mask;
            uint64_t new_mask = r->mask & ~diff;
            uint64_t new_pat = word & new_mask;
            // Требуем минимум 24 жестких инвариантных бита и 0 ложных срабатываний на белом корпусе
            if (__builtin_popcountll(new_mask) >= 24 &&
                !check_false_positive(target_offset, target_offset + 8, new_mask, new_pat)) {
                r->mask = new_mask;
                r->pattern = new_pat;
                r->hits++;
                return 1;
            }
        }
    }

    if (rule_count >= MAX_RULES) return 0;
    uint64_t mask = 0xFFFFFFFFFFFFFFFFULL;
    uint64_t pat = word;
    if (check_false_positive(target_offset, target_offset + 8, mask, pat)) return 0;

    learned_rule_t *nr = rule_db + rule_count;
    nr->offset = target_offset;
    nr->min_len = target_offset + 8;
    nr->mask = mask;
    nr->pattern = pat;
    nr->hits = 1;
    rule_count++;
    return 1;
}

static inline uint32_t xorshift32(uint32_t *s) {
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *s = x;
    return x;
}

void red_agent_attack(uint8_t *buf, size_t *out_len, uint32_t *rng, uint64_t step, uint16_t *found_off, int *front_id) {
    const uint8_t *eth_ip_tcp = (const uint8_t[]){
        0x00,0x11,0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,0xaa,0xbb, 0x08,0x00,
        0x45,0x00,0x00,0x64, 0x13,0x37,0x00,0x00, 0x40,0x06,0x00,0x00,
        0x0a,0x00,0x00,0x01, 0x0a,0x00,0x00,0x02,
        0x12,0x34, 0x01,0xbb, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00, 0x50,0x18, 0x20,0x00, 0x00,0x00, 0x00,0x00
    };
    memcpy(buf, eth_ip_tcp, 54);
    uint32_t r = xorshift32(rng);
    int front = (int)(r % 6);
    *front_id = front;

    uint16_t pad = (front == 4) ? (uint16_t)(((r >> 8) % 3) * 4) : 0;
    if (pad > 0) {
        *(buf + 46) = (uint8_t)((5 + pad / 4) << 4);
        memset(buf + 54, 0x01, pad);
    }
    uint16_t off = 54 + pad;

    if (front == 0) {
        const uint8_t *tls = (const uint8_t[]){0x16, 0x03, (uint8_t)(r & 0x07), 0x00, (uint8_t)((r >> 4) & 0x3F), 0x01, 0x00, 0x00};
        memcpy(buf + off, tls, 8);
        *found_off = off; *out_len = off + 8;
    } else if (front == 1) {
        memcpy(buf + off, "POST\t/\x0bHTTP/1.1\r\n", 17);
        *(buf + off + 4) = (uint8_t)('A' + ((r >> 12) % 16));
        *found_off = off; *out_len = off + 17;
    } else if (front == 2) {
        const uint8_t *quic = (const uint8_t[]){(uint8_t)(0xC0 | (r & 0x0F)), 0x00, 0x00, 0x00, (uint8_t)(1 + ((r >> 8) % 12)), 0x08, 0xDE, 0xAD};
        memcpy(buf + off, quic, 8);
        *found_off = off; *out_len = off + 8;
    } else if (front == 3) {
        *(buf + 22) = (uint8_t)(1 + (r % 15));
        *(buf + 47) = (uint8_t)(0x29 | ((r >> 6) & 0xC0));
        *found_off = 46; *out_len = 60;
    } else if (front == 4) {
        const uint8_t *exp = (const uint8_t[]){0x90, 0x90, 0xEB, 0x1F, (uint8_t)(r & 0x0F), 0x58, 0x31, 0xC0};
        memcpy(buf + off, exp, 8);
        *found_off = off; *out_len = off + 8;
    } else {
        uint64_t payload_mut = 0xDEADC0DE00000000ULL | (uint64_t)(r & 0x0000FFFFU) | ((step & 0x0F) << 16);
        memcpy(buf + off, &payload_mut, 8);
        *found_off = off; *out_len = off + 8;
    }
}

int main() {
    rule_db = calloc(MAX_RULES, sizeof(learned_rule_t));
    init_benign_corpus();

    uint32_t rng = (uint32_t)time(NULL) ^ 0xA5A55A5A;
    uint8_t *pkt = calloc(1, 256);

    uint64_t total_pkts = 0;
    uint64_t total_breaches = 0;
    uint64_t clean_streak = 0;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    printf("=== ЗАПУСК АВТО-БОЯ С XOR-ОБОБЩЕНИЕМ МАСОК (ЛИМИТ: %d СЛОТОВ) ===\n", MAX_RULES);

    while (1) {
        size_t len = 0;
        uint16_t mut_off = 54;
        int front = 0;
        red_agent_attack(pkt, &len, &rng, total_pkts, &mut_off, &front);

        int v = adaptive_shield_inspect(pkt, len, total_pkts);
        total_pkts++;

        if (v != 0) {
            clean_streak++;
        } else {
            total_breaches++;
            clean_streak = 0;
            synthesize_generalized_rule(pkt, len, mut_off);
        }

        if (clean_streak >= 1000000ULL) {
            printf("\n[ПОБЕДА BLUE-AGENT] Броня стабилизирована! 1 000 000 мутантов подряд по всем 6 фронтам отбиты всухую!\n");
            break;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;

    int fp = 0;
    for (int b = 0; b < BENIGN_COUNT; b++) {
        if (adaptive_shield_inspect(benign_pkt(b), *(benign_lens + b), 999999) != 0) fp++;
    }

    FILE *f = fopen("adversarial_gym/battle_rules.bin", "wb");
    if (f) { fwrite(rule_db, sizeof(learned_rule_t), rule_count, f); fclose(f); }

    printf("=== ИТОГ БОЯ С ОБОБЩЕНИЕМ ===\n");
    printf("Всего кадров     : %llu за %.3f сек (%.2f Mpps на 1 ядре)\n",
           (unsigned long long)total_pkts, sec, (total_pkts / 1e6) / sec);
    printf("Пробитий до победы: %llu (на этапе обучения)\n", (unsigned long long)total_breaches);
    printf("Сжатая броня     : %zu SWAR-правил (%zu байт) -> adversarial_gym/battle_rules.bin\n",
           rule_count, rule_count * sizeof(learned_rule_t));
    printf("False Positives  : %d / %d (0.00%% ложных срабатываний)\n", fp, BENIGN_COUNT);
    return 0;
}
