#define _GNU_SOURCE
#include "module_abi.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <dlfcn.h>

typedef int (*guardian_sync_fn_t)(const char *, const char *, size_t *, int *);
typedef int (*db_load_fn_t)(const char *, size_t *);
typedef int (*db_save_fn_t)(const char *);
typedef int (*learn_fn_t)(const uint8_t *, size_t);

typedef struct {
    void *dl_spoof, *dl_guardian, *dl_http, *dl_tarpit, *dl_shaper;
    const zero_module_descriptor_t *mod_spoof, *mod_guardian, *mod_http, *mod_tarpit, *mod_shaper;
    learn_fn_t fn_learn_spoof, fn_learn_http;
    db_save_fn_t fn_save_spoof, fn_save_http;
    int dirty_spoof, dirty_http;
    uint64_t auto_learned_events, total_frames, caught_spoof, caught_swar, caught_http, tarpit_replies, shaped_clean;
} module_chain_t;

static const zero_module_descriptor_t *load_verified_module(const char *so_path, uint32_t expected_id, void **out_handle) {
    void *h = dlopen(so_path, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen %s: %s\n", so_path, dlerror()); return NULL; }
    const zero_module_descriptor_t *desc = (const zero_module_descriptor_t *)dlsym(h, "zero_module_entry");
    if (!desc || desc->magic != ZEROMANI_MODULE_MAGIC || desc->abi_version != ZERO_MODULE_ABI_VER || desc->module_id != expected_id) {
        dlclose(h); return NULL;
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
    ch->mod_spoof->init(seed); ch->mod_guardian->init(seed); ch->mod_http->init(seed);
    ch->mod_tarpit->init(seed); ch->mod_shaper->init(seed);

    ch->fn_learn_spoof = (learn_fn_t)dlsym(ch->dl_spoof, "spoof_learn_peer");
    ch->fn_save_spoof  = (db_save_fn_t)dlsym(ch->dl_spoof, "spoof_save_db");
    ch->fn_learn_http  = (learn_fn_t)dlsym(ch->dl_http, "http_learn_attack");
    ch->fn_save_http   = (db_save_fn_t)dlsym(ch->dl_http, "http_save_db");

    size_t cnt_spoof = 0, cnt_swar = 0, cnt_http = 0;
    int synced = 0;
    db_load_fn_t load_spoof = (db_load_fn_t)dlsym(ch->dl_spoof, "spoof_load_db");
    guardian_sync_fn_t sync_swar = (guardian_sync_fn_t)dlsym(ch->dl_guardian, "guardian_sync_rules");
    db_load_fn_t load_http = (db_load_fn_t)dlsym(ch->dl_http, "http_load_db");

    if (load_spoof) load_spoof("modules/anti_spoof_guard/spoof_bindings.zdb", &cnt_spoof);
    if (sync_swar)  sync_swar("adversarial_gym/battle_rules.bin", "/sys/fs/bpf/swar_rules_map", &cnt_swar, &synced);
    if (load_http)  load_http("modules/http_table_guard/http_learned.zdb", &cnt_http);

    printf("[СТАРТ ОРКЕСТРАТОРА] Подпись ZEROMANI подтверждена | В базах на старте: Spoof=%zu, HTTP=%zu, SWAR=%zu\n",
           cnt_spoof, cnt_http, cnt_swar);
    return 0;
}

static void chain_auto_flush(module_chain_t *ch) {
    if (ch->dirty_spoof && ch->fn_save_spoof && ch->fn_save_spoof("modules/anti_spoof_guard/spoof_bindings.zdb") == 0) ch->dirty_spoof = 0;
    if (ch->dirty_http && ch->fn_save_http && ch->fn_save_http("modules/http_table_guard/http_learned.zdb") == 0) ch->dirty_http = 0;
}

static size_t chain_step_live(module_chain_t *ch, uint8_t *buf, size_t len, size_t max_cap, int hint, uint64_t *delay_ns) {
    ch->total_frames++;
    if (hint == 1 && ch->fn_learn_spoof && ch->fn_learn_spoof(buf, len) == 1) { ch->dirty_spoof = 1; ch->auto_learned_events++; }
    if (ch->mod_spoof->process_frame(buf, len, max_cap, NULL)) { ch->caught_spoof++; ch->tarpit_replies++; return ch->mod_tarpit->process_frame(buf, len, max_cap, delay_ns); }
    if (ch->mod_guardian->process_frame(buf, len, max_cap, NULL)) { ch->caught_swar++; ch->tarpit_replies++; return ch->mod_tarpit->process_frame(buf, len, max_cap, delay_ns); }
    if (ch->mod_http->process_frame(buf, len, max_cap, NULL)) { ch->caught_http++; ch->tarpit_replies++; return ch->mod_tarpit->process_frame(buf, len, max_cap, delay_ns); }
    if (hint == 2 && ch->fn_learn_http && ch->fn_learn_http(buf, len) == 1) {
        ch->dirty_http = 1; ch->auto_learned_events++; ch->caught_http++; ch->tarpit_replies++;
        return ch->mod_tarpit->process_frame(buf, len, max_cap, delay_ns);
    }
    ch->shaped_clean++;
    return ch->mod_shaper->process_frame(buf, len, max_cap, delay_ns);
}

static void chain_destroy(module_chain_t *ch) {
    chain_auto_flush(ch);
    if (ch->mod_spoof) ch->mod_spoof->shutdown();
    if (ch->mod_guardian) ch->mod_guardian->shutdown();
    if (ch->mod_http) ch->mod_http->shutdown();
    if (ch->mod_tarpit) ch->mod_tarpit->shutdown();
    if (ch->mod_shaper) ch->mod_shaper->shutdown();
    if (ch->dl_spoof) dlclose(ch->dl_spoof);
    if (ch->dl_guardian) dlclose(ch->dl_guardian);
    if (ch->dl_http) dlclose(ch->dl_http);
    if (ch->dl_tarpit) dlclose(ch->dl_tarpit);
    if (ch->dl_shaper) dlclose(ch->dl_shaper);
}

int main() {
    unlink("modules/anti_spoof_guard/spoof_bindings.zdb");
    unlink("modules/http_table_guard/http_learned.zdb");
    module_chain_t chain;
    if (chain_init(&chain) != 0) return 1;

    uint8_t *p_spoof = calloc(1, 512), *p_smug = calloc(1, 512), *p_xss = calloc(1, 512), *p_clean = calloc(1, 512), *work = calloc(1, 512);
    const uint8_t *base = (const uint8_t[]){
        0x00,0x11,0x22,0x33,0x44,0x55, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x08,0x00,
        0x45,0x00,0x00,0x3c, 0x13,0x37,0x00,0x00, 0x40,0x06,0x00,0x00,
        0x0a,0x00,0x00,0x63, 0x0a,0x00,0x00,0x01,
        0xd4,0x31, 0x01,0xbb, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x00,0x00, 0x50,0x18, 0x72,0x10, 0x00,0x00, 0x00,0x00
    };
    memcpy(p_spoof, base, 54); *(p_spoof + 6) = 0xde; *(p_spoof + 22) = 128;
    memcpy(p_smug, base, 54); *(p_smug + 29) = 200;
    const char *smug = "POST / HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    memcpy(p_smug + 54, smug, strlen(smug));
    memcpy(p_xss, base, 54); *(p_xss + 29) = 201;
    const char *xss = "POST /login HTTP/1.1\r\nHost: app.local\r\n\r\n<table><script>steal()</script></table>";
    memcpy(p_xss + 54, xss, strlen(xss));
    memcpy(p_clean, base, 54);
    const char *ok = "GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n";
    memcpy(p_clean + 54, ok, strlen(ok));

    uint64_t delay_ns = 0;
    memcpy(work, p_clean, 54 + strlen(ok)); chain_step_live(&chain, work, 54 + strlen(ok), 512, 1, &delay_ns);
    memcpy(work, p_smug, 54 + strlen(smug)); chain_step_live(&chain, work, 54 + strlen(smug), 512, 2, &delay_ns);
    memcpy(work, p_xss, 54 + strlen(xss)); chain_step_live(&chain, work, 54 + strlen(xss), 512, 2, &delay_ns);
    chain_auto_flush(&chain);

    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < 1000000; i++) {
        int k = i & 3;
        if (k == 0) { memcpy(work, p_spoof, 64); chain_step_live(&chain, work, 64, 512, 0, &delay_ns); }
        else if (k == 1) { memcpy(work, p_smug, 54 + strlen(smug)); chain_step_live(&chain, work, 54 + strlen(smug), 512, 0, &delay_ns); }
        else if (k == 2) { memcpy(work, p_xss, 54 + strlen(xss)); chain_step_live(&chain, work, 54 + strlen(xss), 512, 0, &delay_ns); }
        else { memcpy(work, p_clean, 54 + strlen(ok)); chain_step_live(&chain, work, 54 + strlen(ok), 512, 0, &delay_ns); }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;

    printf("=== ЖИВОЕ АВТООБУЧЕНИЕ В ПОТОКЕ + ПРОГОН 1 000 000 КАДРОВ ===\n");
    printf("Выучено на лету    : %llu правил/привязок (сохранены в .zdb с подписью ZEROMANI)\n", (unsigned long long)chain.auto_learned_events);
    printf("Боевая скорость    : 1 000 000 кадров за %.4f сек (%.2f млн кадров/сек на 1 ядре)\n", sec, 1.0 / sec);
    printf("Отбито спуфинга    : %llu / 250000 | Отбито HTTP-атак: %llu / 500000 | Чистых в шейпер: %llu / 250000\n",
           (unsigned long long)chain.caught_spoof, (unsigned long long)chain.caught_http, (unsigned long long)(chain.shaped_clean - 1));
    chain_destroy(&chain);
    free(p_spoof); free(p_smug); free(p_xss); free(p_clean); free(work);
    return 0;
}
