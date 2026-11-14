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
typedef int (*wd_watch_fn_t)(const char *);

typedef struct {
    void *dl_spoof, *dl_guardian, *dl_http, *dl_tarpit, *dl_shaper, *dl_wd;
    const zero_module_descriptor_t *mod_spoof, *mod_guardian, *mod_http, *mod_tarpit, *mod_shaper, *mod_wd;
    learn_fn_t fn_learn_spoof, fn_learn_http;
    db_save_fn_t fn_save_spoof, fn_save_http;
    wd_watch_fn_t fn_wd_watch;
    int dirty_spoof, dirty_http;
    uint64_t auto_learned_events, wd_alerts, total_frames, caught_spoof, caught_swar, caught_http, tarpit_replies, shaped_clean;
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
    ch->mod_wd       = load_verified_module("/tmp/libmod_ai_wd.so", 6, &ch->dl_wd);
    if (!ch->mod_spoof || !ch->mod_guardian || !ch->mod_http || !ch->mod_tarpit || !ch->mod_shaper || !ch->mod_wd) return -1;

    uint64_t seed = ZEROMANI_MODULE_MAGIC;
    ch->mod_spoof->init(seed); ch->mod_guardian->init(seed); ch->mod_http->init(seed);
    ch->mod_tarpit->init(seed); ch->mod_shaper->init(seed); ch->mod_wd->init(seed);

    ch->fn_learn_spoof = (learn_fn_t)dlsym(ch->dl_spoof, "spoof_learn_peer");
    ch->fn_save_spoof  = (db_save_fn_t)dlsym(ch->dl_spoof, "spoof_save_db");
    ch->fn_learn_http  = (learn_fn_t)dlsym(ch->dl_http, "http_learn_attack");
    ch->fn_save_http   = (db_save_fn_t)dlsym(ch->dl_http, "http_save_db");
    ch->fn_wd_watch    = (wd_watch_fn_t)dlsym(ch->dl_wd, "watchdog_watch_dir");
    if (ch->fn_wd_watch) { ch->fn_wd_watch("src"); ch->fn_wd_watch("modules"); }

    size_t cnt_spoof = 0, cnt_swar = 0, cnt_http = 0; int synced = 0;
    db_load_fn_t load_spoof = (db_load_fn_t)dlsym(ch->dl_spoof, "spoof_load_db");
    guardian_sync_fn_t sync_swar = (guardian_sync_fn_t)dlsym(ch->dl_guardian, "guardian_sync_rules");
    db_load_fn_t load_http = (db_load_fn_t)dlsym(ch->dl_http, "http_load_db");
    if (load_spoof) load_spoof("modules/anti_spoof_guard/spoof_bindings.zdb", &cnt_spoof);
    if (sync_swar)  sync_swar("adversarial_gym/battle_rules.bin", "/sys/fs/bpf/swar_rules_map", &cnt_swar, &synced);
    if (load_http)  load_http("modules/http_table_guard/http_learned.zdb", &cnt_http);

    printf("[ОРКЕСТРАТОР 6-В-1] Все 6 модулей подтвердили подпись ZEROMANI | Базы: Spoof=%zu, HTTP=%zu, SWAR=%zu | Сторож ФС: АКТИВЕН\n",
           cnt_spoof, cnt_http, cnt_swar);
    return 0;
}

static void chain_auto_flush(module_chain_t *ch) {
    if (ch->dirty_spoof && ch->fn_save_spoof && ch->fn_save_spoof("modules/anti_spoof_guard/spoof_bindings.zdb") == 0) ch->dirty_spoof = 0;
    if (ch->dirty_http && ch->fn_save_http && ch->fn_save_http("modules/http_table_guard/http_learned.zdb") == 0) ch->dirty_http = 0;
}

static size_t chain_step_live(module_chain_t *ch, uint8_t *buf, size_t len, size_t max_cap, int hint, uint64_t *delay_ns) {
    ch->total_frames++;
    if ((ch->total_frames & 0xFFFFULL) == 0 && ch->mod_wd) ch->wd_alerts += ch->mod_wd->process_frame(NULL, 0, 0, NULL);
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
    if (ch->mod_wd) ch->mod_wd->shutdown();
    if (ch->dl_spoof) dlclose(ch->dl_spoof);
    if (ch->dl_guardian) dlclose(ch->dl_guardian);
    if (ch->dl_http) dlclose(ch->dl_http);
    if (ch->dl_tarpit) dlclose(ch->dl_tarpit);
    if (ch->dl_shaper) dlclose(ch->dl_shaper);
    if (ch->dl_wd) dlclose(ch->dl_wd);
}

int main() {
    module_chain_t chain;
    if (chain_init(&chain) != 0) return 1;
    system("mkdir -p /tmp/wd_orch_zone && touch /tmp/wd_orch_zone/secret.rs");
    if (chain.fn_wd_watch) chain.fn_wd_watch("/tmp/wd_orch_zone");
    unlink("/tmp/wd_orch_zone/secret.rs");

    uint8_t *work = calloc(1, 512);
    const uint8_t *base = (const uint8_t[]){
        0x00,0x11,0x22,0x33,0x44,0x55, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x08,0x00,
        0x45,0x00,0x00,0x3c, 0x13,0x37,0x00,0x00, 0x40,0x06,0x00,0x00,
        0x0a,0x00,0x00,0x63, 0x0a,0x00,0x00,0x01,
        0xd4,0x31, 0x01,0xbb, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x00,0x00, 0x50,0x18, 0x72,0x10, 0x00,0x00, 0x00,0x00
    };
    const char *ok = "GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n";
    uint64_t delay_ns = 0;
    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < 1000000; i++) {
        memcpy(work, base, 54); memcpy(work + 54, ok, strlen(ok));
        chain_step_live(&chain, work, 54 + strlen(ok), 512, 0, &delay_ns);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;
    printf("=== ПОЛНЫЙ 6-МОДУЛЬНЫЙ ОРКЕСТРАТОР (1 000 000 КАДРОВ + СТОРОЖ ФС) ===\n");
    printf("Скорость конвейера : %.2f млн кадров/сек | Перехвачено диверсий ФС: %llu\n", 1.0 / sec, (unsigned long long)chain.wd_alerts);
    chain_destroy(&chain);
    system("rm -rf /tmp/wd_orch_zone");
    free(work);
    return 0;
}
