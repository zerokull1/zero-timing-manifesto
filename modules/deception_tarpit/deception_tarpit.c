#include "../module_abi.h"
#include <string.h>

static uint64_t tarpit_seed = 0;

static inline uint16_t bswap16(uint16_t v) {
    return (uint16_t)((v << 8) | (v >> 8));
}

static inline uint32_t bswap32(uint32_t v) {
    return ((v & 0xFF000000U) >> 24) |
           ((v & 0x00FF0000U) >> 8)  |
           ((v & 0x0000FF00U) << 8)  |
           ((v & 0x000000FFU) << 24);
}

static uint16_t ipv4_checksum(const uint8_t *hdr) {
    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2) {
        if (i == 10) continue;
        uint16_t w = (uint16_t)((*(hdr + i) << 8) | *(hdr + i + 1));
        sum += w;
    }
    while (sum >> 16) sum = (sum & 0xFFFFU) + (sum >> 16);
    return (uint16_t)(~sum);
}

static int tarpit_init(uint64_t seed) {
    tarpit_seed = seed ^ ZEROMANI_MODULE_MAGIC;
    return 0;
}

// Превращает входящий кадр сканера/бота в ответный TCP ACK с нулевым окном (Zero-Window Tarpit)
static size_t tarpit_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns) {
    (void)max_cap;
    if (!buf || len < 54) return 0;

    // Проверяем EtherType = IPv4 (0x0800) и протокол = TCP (6)
    if (*(buf + 12) != 0x08 || *(buf + 13) != 0x00 || *(buf + 23) != 6) return 0;

    // 1. Меняем местами MAC-адреса (6 байт)
    uint8_t tmp_mac0 = *(buf + 0), tmp_mac1 = *(buf + 1), tmp_mac2 = *(buf + 2);
    uint8_t tmp_mac3 = *(buf + 3), tmp_mac4 = *(buf + 4), tmp_mac5 = *(buf + 5);
    memcpy(buf + 0, buf + 6, 6);
    *(buf + 6) = tmp_mac0; *(buf + 7) = tmp_mac1; *(buf + 8) = tmp_mac2;
    *(buf + 9) = tmp_mac3; *(buf + 10) = tmp_mac4; *(buf + 11) = tmp_mac5;

    // 2. Меняем местами IPv4 адреса источника и назначения (смещения 26 и 30)
    uint32_t src_ip = 0, dst_ip = 0;
    memcpy(&src_ip, buf + 26, 4);
    memcpy(&dst_ip, buf + 30, 4);
    memcpy(buf + 26, &dst_ip, 4);
    memcpy(buf + 30, &src_ip, 4);

    // Общая длина IPv4 = 40 байт (20 IP + 20 TCP), TTL = 64
    *(buf + 16) = 0x00;
    *(buf + 17) = 40;
    *(buf + 22) = 64;
    uint16_t ip_csum = ipv4_checksum(buf + 14);
    *(buf + 24) = (uint8_t)(ip_csum >> 8);
    *(buf + 25) = (uint8_t)(ip_csum & 0xFF);

    // 3. Меняем местами TCP-порты (смещения 34 и 36)
    uint16_t src_port = 0, dst_port = 0;
    memcpy(&src_port, buf + 34, 2);
    memcpy(&dst_port, buf + 36, 2);
    memcpy(buf + 34, &dst_port, 2);
    memcpy(buf + 36, &src_port, 2);

    // 4. Формируем Seq / Ack и зажимаем TCP Window = 0 (липкая ловушка)
    uint32_t in_seq = 0;
    memcpy(&in_seq, buf + 38, 4);
    uint32_t ack_num = bswap32(bswap32(in_seq) + 1U);
    uint32_t syn_seq = (uint32_t)(tarpit_seed ^ bswap32(src_ip));

    memcpy(buf + 38, &syn_seq, 4);
    memcpy(buf + 42, &ack_num, 4);

    *(buf + 46) = 0x50; // Data Offset = 5 (20 байт)
    *(buf + 47) = 0x10; // Флаг ACK
    *(buf + 48) = 0x00; // TCP Window старший байт = 0
    *(buf + 49) = 0x00; // TCP Window младший байт = 0 (ловушка!)
    *(buf + 50) = 0x00;
    *(buf + 51) = 0x00;

    if (out_delay_ns) *out_delay_ns = 0;
    return 54;
}

static void tarpit_shutdown(void) {
    tarpit_seed = 0;
}

const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC,
    .abi_version = ZERO_MODULE_ABI_VER,
    .module_id = 1,
    .name = "deception_zero_window_tarpit",
    .init = tarpit_init,
    .process_frame = tarpit_process_frame,
    .shutdown = tarpit_shutdown
};
