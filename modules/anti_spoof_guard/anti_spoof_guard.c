#include "../module_abi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SPOOF_SLOTS 256

typedef struct __attribute__((packed)) {
    uint32_t src_ip;
    uint64_t mac_ttl_sig; // упакованные 6 байт MAC + 1 байт TTL + флаг активности
    uint32_t seen_count;
} spoof_binding_t;

static spoof_binding_t *bindings = NULL;
static size_t learned_peers = 0;

static inline uint64_t pack_mac_ttl(const uint8_t *mac, uint8_t ttl) {
    uint64_t sig = 0x0100000000000000ULL | ((uint64_t)ttl << 48);
    sig |= ((uint64_t)(*(mac + 0)) << 40);
    sig |= ((uint64_t)(*(mac + 1)) << 32);
    sig |= ((uint64_t)(*(mac + 2)) << 24);
    sig |= ((uint64_t)(*(mac + 3)) << 16);
    sig |= ((uint64_t)(*(mac + 4)) << 8);
    sig |= ((uint64_t)(*(mac + 5)));
    return sig;
}

static inline uint32_t slot_index(uint32_t ip) {
    uint32_t h = ip * 2654435761U;
    return (h >> 24) & (SPOOF_SLOTS - 1);
}

static int spoof_init(uint64_t seed) {
    (void)seed;
    if (!bindings) bindings = calloc(SPOOF_SLOTS, sizeof(spoof_binding_t));
    learned_peers = 0;
    return bindings ? 0 : -1;
}

// Загрузка выученных привязок MAC+IP+TTL с проверкой авторской подписи ZEROMANI
int spoof_load_db(const char *path, size_t *out_count) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (out_count) *out_count = 0;
        return -1;
    }
    uint64_t hdr = 0;
    if (fread(&hdr, 8, 1, f) != 1 || hdr != ZEROMANI_MODULE_MAGIC) {
        fclose(f);
        return -2;
    }
    if (!bindings) bindings = calloc(SPOOF_SLOTS, sizeof(spoof_binding_t));
    memset(bindings, 0, SPOOF_SLOTS * sizeof(spoof_binding_t));
    learned_peers = 0;

    spoof_binding_t entry;
    while (fread(&entry, sizeof(entry), 1, f) == 1) {
        if (entry.mac_ttl_sig != 0) {
            uint32_t idx = slot_index(entry.src_ip);
            for (uint32_t step = 0; step < SPOOF_SLOTS; step++) {
                uint32_t pos = (idx + step) & (SPOOF_SLOTS - 1);
                spoof_binding_t *slot = bindings + pos;
                if (slot->mac_ttl_sig == 0) {
                    *slot = entry;
                    learned_peers++;
                    break;
                }
            }
        }
    }
    fclose(f);
    if (out_count) *out_count = learned_peers;
    return 0;
}

// Сохранение выученной базы привязок на диск с меткой ZEROMANI
int spoof_save_db(const char *path) {
    if (!bindings) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    uint64_t hdr = ZEROMANI_MODULE_MAGIC;
    fwrite(&hdr, 8, 1, f);
    for (size_t i = 0; i < SPOOF_SLOTS; i++) {
        spoof_binding_t *slot = bindings + i;
        if (slot->mac_ttl_sig != 0) {
            fwrite(slot, sizeof(*slot), 1, f);
        }
    }
    fclose(f);
    return 0;
}

// Режим обучения на доверенном сегменте: запоминает связку (Src_IP -> Src_MAC + TTL)
int spoof_learn_peer(const uint8_t *buf, size_t len) {
    if (!bindings || !buf || len < 34) return -1;
    if (*(buf + 12) != 0x08 || *(buf + 13) != 0x00) return 0; // только IPv4

    uint32_t src_ip = 0;
    memcpy(&src_ip, buf + 26, 4);
    uint8_t ttl = *(buf + 22);
    uint64_t sig = pack_mac_ttl(buf + 6, ttl);

    uint32_t idx = slot_index(src_ip);
    for (uint32_t step = 0; step < SPOOF_SLOTS; step++) {
        uint32_t pos = (idx + step) & (SPOOF_SLOTS - 1);
        spoof_binding_t *slot = bindings + pos;
        if (slot->mac_ttl_sig == 0) {
            slot->src_ip = src_ip;
            slot->mac_ttl_sig = sig;
            slot->seen_count = 1;
            learned_peers++;
            return 1;
        }
        if (slot->src_ip == src_ip) {
            slot->mac_ttl_sig = sig;
            slot->seen_count++;
            return 0;
        }
    }
    return -2;
}

// Боевая проверка кадра за O(1): возвращает 1 при обнаружении спуфинга MAC/IP/TTL
static size_t spoof_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns) {
    (void)max_cap;
    if (out_delay_ns) *out_delay_ns = 0;
    if (!bindings || !buf || len < 34) return 0;
    if (*(buf + 12) != 0x08 || *(buf + 13) != 0x00) return 0;

    uint32_t src_ip = 0;
    memcpy(&src_ip, buf + 26, 4);
    uint8_t ttl = *(buf + 22);
    uint64_t sig = pack_mac_ttl(buf + 6, ttl);

    uint32_t idx = slot_index(src_ip);
    for (uint32_t step = 0; step < 8; step++) {
        uint32_t pos = (idx + step) & (SPOOF_SLOTS - 1);
        spoof_binding_t *slot = bindings + pos;
        if (slot->mac_ttl_sig == 0) return 0; // неизвестный внешний узел
        if (slot->src_ip == src_ip) {
            return (slot->mac_ttl_sig != sig) ? 1 : 0; // несовпадение MAC или TTL = СПУФИНГ!
        }
    }
    return 0;
}

static void spoof_shutdown(void) {
    if (bindings) {
        memset(bindings, 0, SPOOF_SLOTS * sizeof(spoof_binding_t));
        free(bindings);
        bindings = NULL;
    }
    learned_peers = 0;
}

const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC,
    .abi_version = ZERO_MODULE_ABI_VER,
    .module_id = 5,
    .name = "adaptive_anti_spoof_guard",
    .init = spoof_init,
    .process_frame = spoof_process_frame,
    .shutdown = spoof_shutdown
};
