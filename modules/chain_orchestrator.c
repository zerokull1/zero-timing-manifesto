#define _GNU_SOURCE
#include "module_abi.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>

typedef int (*guardian_sync_fn_t)(const char *, const char *, size_t *, int *);
typedef int (*db_load_fn_t)(const char *, size_t *);

typedef struct {
    void *dl_spoof;
    void *dl_guardian;
    void *dl_http;
    void *dl_tarpit;
    void *dl_shaper;
    const zero_module_descriptor_t *mod_spoof;
    const zero_module_descriptor_t *mod_guardian;
    const zero_module_descriptor_t *mod_http;
    const zero_module_descriptor_t *mod_tarpit;
    const zero_module_descriptor_t *mod_shaper;
    uint64_t total_frames;
    uint64_t caught_spoof;
    uint64_t caught_swar;
    uint64_t caught_http;
    uint64_t tarpit_replies;
    uint64_t shaped_clean;
} module_chain_t;

static const zero_module_descriptor_t *load_verified_module(const char *so_path, uint32_t expected_id, void **out_handle) {
    void *h = dlopen(so_path, RTLD_NOW);
    if (!h) {
        fprintf(stderr, "Ошибка dlopen (%s): %s\n", so_path, dlerror());
        return NULL;
    }
    const zero_module_descriptor_t *desc = (const zero_module_descriptor_t *)dlsym(h, "zero_module_entry");
    if (!desc || desc->magic != ZEROMANI_MODULE_MAGIC || desc->abi_version != ZERO_MODULE_ABI_VER || desc->module_id != expected_id) {
        fprintf(stderr, "ТРЕВОГА: неверная авторская подпись ZEROMANI или ABI у модуля %s!\n", so_path);
        dlclose(h);
        return NULL;
    }
    *out_handle = h;
    return desc;
}

static int chain_init(module_chain_t *ch) {
    memset(ch, 0, sizeof(*ch));
    ch->mod_spoof    = load_verified_module("/tmp/libmod_anti_spoof.so", 5, &ch->dl_spoof);
    ch->mod_guardian = load_verified_module("/tmp/libmod_xdp_guardian.so", 2, &ch->dl_guardian);
    ch->mod_http     = load_verified_module("/tmp/libmod_http_guard.so", 4, &ch->dl_http);
    ch->mod_tarpit   = load_verified_module("/tmp/libmod_deception_tarpit.so", 1, &ch->dl_tarpit);
    ch->mod_shaper   = load_verified_module("/tmp/libmod_entropy_shaper.so", 3, &ch->dl_shaper);
    if (!ch->mod_spoof || !ch->mod_guardian || !ch->mod_http || !ch->mod_tarpit || !ch->mod_shaper) return -1;

    uint64_t seed = ZEROMANI_MODULE_MAGIC;
    ch->mod_spoof->init(seed);
    ch->mod_guardian->init(seed);
    ch->mod_http->init(seed);
    ch->mod_tarpit->init(seed);
    ch->mod_shaper->init(seed);

    size_t cnt_spoof = 0, cnt_swar = 0, cnt_http = 0;
    int synced = 0;

    db_load_fn_t load_spoof = (db_load_fn_t)dlsym(ch->dl_spoof, "spoof_load_db");
    guardian_sync_fn_t sync_swar = (guardian_sync_fn_t)dlsym(ch->dl_guardian, "guardian_sync_rules");
    db_load_fn_t load_http = (db_load_fn_t)dlsym(ch->dl_http, "http_load_db");

    if (load_spoof) load_spoof("modules/anti_spoof_guard/spoof_bindings.zdb", &cnt_spoof);
    if (sync_swar)  sync_swar("adversarial_gym/battle_rules.bin", "/sys/fs/bpf/swar_rules_map", &cnt_swar, &synced);
    if (load_http)  load_http("modules/http_table_guard/http_learned.zdb", &cnt_http);

    printf("[ОРКЕСТРАТОР 5-В-1] Все 5 модулей подтвердили подпись ZEROMANI | Базы с диска: Spoof=%zu, SWAR=%zu, HTTP=%zu\n",
           cnt_spoof, cnt_swar, cnt_http);
    return 0;
}

static size_t chain_step(module_chain_t *ch, uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns) {
    ch->total_frames++;

    if (ch->mod_spoof->process_frame(buf, len, max_cap, NULL)) {
        ch->caught_spoof++;
        ch->tarpit_replies++;
        return ch->mod_tarpit->process_frame(buf, len, max_cap, out_delay_ns);
    }
    if (ch->mod_guardian->process_frame(buf, len, max_cap, NULL)) {
        ch->caught_swar++;
        ch->tarpit_replies++;
        return ch->mod_tarpit->process_frame(buf, len, max_cap, out_delay_ns);
    }
    if (ch->mod_http->process_frame(buf, len, max_cap, NULL)) {
        ch->caught_http++;
        ch->tarpit_replies++;
        return ch->mod_tarpit->process_frame(buf, len, max_cap, out_delay_ns);
    }

    ch->shaped_clean++;
    return ch->mod_shaper->process_frame(buf, len, max_cap, out_delay_ns);
}

static void chain_destroy(module_chain_t *ch) {
    if (ch->mod_spoof)    ch->mod_spoof->shutdown();
    if (ch->mod_guardian) ch->mod_guardian->shutdown();
    if (ch->mod_http)     ch->mod_http->shutdown();
    if (ch->mod_tarpit)   ch->mod_tarpit->shutdown();
    if (ch->mod_shaper)   ch->mod_shaper->shutdown();
    if (ch->dl_spoof)     dlclose(ch->dl_spoof);
    if (ch->dl_guardian)  dlclose(ch->dl_guardian);
    if (ch->dl_http)      dlclose(ch->dl_http);
    if (ch->dl_tarpit)    dlclose(ch->dl_tarpit);
    if (ch->dl_shaper)    dlclose(ch->dl_shaper);
}

int main() {
    module_chain_t chain;
    if (chain_init(&chain) != 0) return 1;

    uint8_t *p_spoof = calloc(1, 512);
    uint8_t *p_scan  = calloc(1, 512);
    uint8_t *p_http  = calloc(1, 512);
    uint8_t *p_clean = calloc(1, 512);
    uint8_t *work    = calloc(1, 512);

    const uint8_t *base_clean = (const uint8_t[]){
        0x00,0x11,0x22,0x33,0x44,0x55, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x08,0x00,
        0x45,0x00,0x00,0x3c, 0x13,0x37,0x00,0x00, 0x40,0x06,0x00,0x00,
        0x0a,0x00,0x00,0x63, 0x0a,0x00,0x00,0x01,
        0xd4,0x31, 0x01,0xbb, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x00,0x00, 0x50,0x18, 0x72,0x10, 0x00,0x00, 0x00,0x00
    };

    // 1) Спуфинг MAC+TTL от известного IP 10.0.0.99
    memcpy(p_spoof, base_clean, 54);
    *(p_spoof + 6) = 0xde; *(p_spoof + 22) = 128;

    // 2) Сетевой скан (Xmas flags 0x29)
    memcpy(p_scan, base_clean, 54);
    *(p_scan + 22) = 5; *(p_scan + 47) = 0x29; *(p_scan + 48) = 0x20; *(p_scan + 49) = 0x00;

    // 3) HTTP Request Smuggling (CL + TE)
    memcpy(p_http, base_clean, 54);
    const char *smug = "POST / HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    size_t smug_len = strlen(smug);
    memcpy(p_http + 54, smug, smug_len);

    // 4) Легитимный HTTP-запрос
    memcpy(p_clean, base_clean, 54);
    const char *ok_http = "GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n";
    size_t ok_len = strlen(ok_http);
    memcpy(p_clean + 54, ok_http, ok_len);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    uint64_t delay_ns = 0;
    for (int i = 0; i < 1000000; i++) {
        int kind = i & 3;
        if (kind == 0) {
            memcpy(work, p_spoof, 64);
            chain_step(&chain, work, 64, 512, &delay_ns);
        } else if (kind == 1) {
            memcpy(work, p_scan, 64);
            chain_step(&chain, work, 64, 512, &delay_ns);
        } else if (kind == 2) {
            memcpy(work, p_http, 54 + smug_len);
            chain_step(&chain, work, 54 + smug_len, 512, &delay_ns);
        } else {
            memcpy(work, p_clean, 54 + ok_len);
            chain_step(&chain, work, 54 + ok_len, 512, &delay_ns);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;

    printf("=== ПОЛНЫЙ 5-МОДУЛЬНЫЙ КОНВЕЙЕР (1 000 000 СМЕШАННЫХ КАДРОВ) ===\n");
    printf("Общая скорость     : 1 000 000 кадров за %.4f сек (%.2f млн кадров/сек на 1 ядре)\n",
           sec, 1.0 / sec);
    printf("Поймано спуфинга   : %llu -> в тарпит\n", (unsigned long long)chain.caught_spoof);
    printf("Поймано SWAR-сканов: %llu -> в тарпит\n", (unsigned long long)chain.caught_swar);
    printf("Поймано HTTP-атак  : %llu -> в тарпит\n", (unsigned long long)chain.caught_http);
    printf("Всего в тарпит     : %llu (заморозка TCP Window = 0)\n", (unsigned long long)chain.tarpit_replies);
    printf("Чистых в шейпер    : %llu (сглажены энтропия и джиттер IAT)\n", (unsigned long long)chain.shaped_clean);

    chain_destroy(&chain);
    free(p_spoof); free(p_scan); free(p_http); free(p_clean); free(work);
    return 0;
}
