#include "../module_abi.h"
#include <string.h>

static uint64_t egress_key = 0;
static uint64_t pkt_seq_counter = 0;

static inline uint64_t splitmix64(uint64_t *x) {
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static int egress_init(uint64_t seed) {
    egress_key = seed ^ ZEROMANI_MODULE_MAGIC;
    pkt_seq_counter = 1;
    return 0;
}

// Мутация пакета перед выходом из сетевой карты (TX): меняет L2 MAC, IP ID/TTL и шифрует L7 HTTP/HTTPS/TLS
static size_t egress_mutate_tx(uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns) {
    (void)max_cap;
    if (out_delay_ns) *out_delay_ns = 0;
    if (!buf || len < 54) return len;

    uint64_t st = egress_key ^ (pkt_seq_counter++);
    uint64_t g0 = splitmix64(&st);

    // 1. Мутация младших байтов MAC (смещения 3..5 и 9..11, сохраняя unicast-бит)
    *(buf + 3) ^= (uint8_t)(g0 & 0xFF);
    *(buf + 4) ^= (uint8_t)((g0 >> 8) & 0xFF);
    *(buf + 9) ^= (uint8_t)((g0 >> 16) & 0xFF);

    // 2. Мутация IPv4 Identification (смещение 18..19) и плавающий TTL (57..64, смещение 22)
    *(buf + 18) ^= (uint8_t)((g0 >> 24) & 0xFF);
    *(buf + 19) ^= (uint8_t)((g0 >> 32) & 0xFF);
    *(buf + 22) = (uint8_t)(57 + ((g0 >> 40) & 0x07));

    // 3. Мутация всей полезной нагрузки L7 (HTTP-заголовки или HTTPS/TLS ClientHello) потоковой гаммой
    size_t pos = 54;
    while (pos + 8 <= len) {
        uint64_t w = 0, gamma = splitmix64(&st);
        memcpy(&w, buf + pos, 8);
        w ^= gamma;
        memcpy(buf + pos, &w, 8);
        pos += 8;
    }
    if (pos < len) {
        uint64_t gamma = splitmix64(&st);
        uint8_t *gb = (uint8_t *)&gamma;
        for (size_t r = 0; pos + r < len; r++) *(buf + pos + r) ^= *(gb + r);
    }
    return len;
}

// Симметричное восстановление мутированного кадра на парном узле (RX) с тем же ключом ZEROMANI
size_t egress_demutate_rx(uint8_t *buf, size_t len, uint64_t seq_num, uint8_t orig_ttl) {
    if (!buf || len < 54) return len;
    uint64_t st = egress_key ^ seq_num;
    uint64_t g0 = splitmix64(&st);

    *(buf + 3) ^= (uint8_t)(g0 & 0xFF);
    *(buf + 4) ^= (uint8_t)((g0 >> 8) & 0xFF);
    *(buf + 9) ^= (uint8_t)((g0 >> 16) & 0xFF);
    *(buf + 18) ^= (uint8_t)((g0 >> 24) & 0xFF);
    *(buf + 19) ^= (uint8_t)((g0 >> 32) & 0xFF);
    *(buf + 22) = orig_ttl;

    size_t pos = 54;
    while (pos + 8 <= len) {
        uint64_t w = 0, gamma = splitmix64(&st);
        memcpy(&w, buf + pos, 8);
        w ^= gamma;
        memcpy(buf + pos, &w, 8);
        pos += 8;
    }
    if (pos < len) {
        uint64_t gamma = splitmix64(&st);
        uint8_t *gb = (uint8_t *)&gamma;
        for (size_t r = 0; pos + r < len; r++) *(buf + pos + r) ^= *(gb + r);
    }
    return len;
}

static void egress_shutdown(void) { egress_key = 0; pkt_seq_counter = 0; }

const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC, .abi_version = ZERO_MODULE_ABI_VER, .module_id = 9,
    .name = "egress_wire_protocol_mutator", .init = egress_init,
    .process_frame = egress_mutate_tx, .shutdown = egress_shutdown
};
