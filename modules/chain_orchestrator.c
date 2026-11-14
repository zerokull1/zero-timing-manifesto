#define _GNU_SOURCE
#include "module_abi.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>

typedef int (*guardian_sync_fn_t)(const char *, const char *, size_t *, int *);

typedef struct {
    void *dl_guardian;
    void *dl_tarpit;
    void *dl_shaper;
    const zero_module_descriptor_t *mod_guardian;
    const zero_module_descriptor_t *mod_tarpit;
    const zero_module_descriptor_t *mod_shaper;
    uint64_t total_frames;
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

static int chain_init(module_chain_t *ch, const char *so_guard, const char *so_tarpit, const char *so_shaper, const char *rules_bin) {
    memset(ch, 0, sizeof(*ch));
    ch->mod_guardian = load_verified_module(so_guard, 2, &ch->dl_guardian);
    ch->mod_tarpit   = load_verified_module(so_tarpit, 1, &ch->dl_tarpit);
    ch->mod_shaper   = load_verified_module(so_shaper, 3, &ch->dl_shaper);
    if (!ch->mod_guardian || !ch->mod_tarpit || !ch->mod_shaper) return -1;

    uint64_t seed = 0x5A45524F4D414E49ULL;
    if (ch->mod_guardian->init(seed) != 0 || ch->mod_tarpit->init(seed) != 0 || ch->mod_shaper->init(seed) != 0) {
        return -2;
    }

    guardian_sync_fn_t sync_fn = (guardian_sync_fn_t)dlsym(ch->dl_guardian, "guardian_sync_rules");
    size_t loaded = 0;
    int synced = 0;
    if (!sync_fn || sync_fn(rules_bin, "/sys/fs/bpf/swar_rules_map", &loaded, &synced) != 0) {
        fprintf(stderr, "Ошибка загрузки правил %s в сторож цепочки!\n", rules_bin);
        return -3;
    }
    printf("[ОРКЕСТРАТОР] Все 3 модуля прошли проверку подписи ZEROMANI (загружено %zu SWAR-правил).\n", loaded);
    return 0;
}

// Единый проход пакета через цепочку: Сторож -> (если атака: Тарпит) / (если чистый: Шейпер энтропии)
static size_t chain_step(module_chain_t *ch, uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns, int *out_action) {
    ch->total_frames++;
    size_t is_threat = ch->mod_guardian->process_frame(buf, len, max_cap, NULL);
    if (is_threat) {
        ch->tarpit_replies++;
        if (out_action) *out_action = 2; // ответ-ловушка TCP Zero-Window
        return ch->mod_tarpit->process_frame(buf, len, max_cap, out_delay_ns);
    } else {
        ch->shaped_clean++;
        if (out_action) *out_action = 1; // легитимный кадр со сглаженной энтропией
        return ch->mod_shaper->process_frame(buf, len, max_cap, out_delay_ns);
    }
}

static void chain_destroy(module_chain_t *ch) {
    if (ch->mod_guardian) ch->mod_guardian->shutdown();
    if (ch->mod_tarpit)   ch->mod_tarpit->shutdown();
    if (ch->mod_shaper)   ch->mod_shaper->shutdown();
    if (ch->dl_guardian)  dlclose(ch->dl_guardian);
    if (ch->dl_tarpit)    dlclose(ch->dl_tarpit);
    if (ch->dl_shaper)    dlclose(ch->dl_shaper);
}

int main() {
    module_chain_t chain;
    if (chain_init(&chain,
                   "/tmp/libmod_xdp_guardian.so",
                   "/tmp/libmod_deception_tarpit.so",
                   "/tmp/libmod_entropy_shaper.so",
                   "adversarial_gym/battle_rules.bin") != 0) {
        return 1;
    }

    uint8_t *pkt_atk = calloc(1, 2048);
    uint8_t *pkt_ok  = calloc(1, 2048);
    uint8_t *work    = calloc(1, 2048);

    const uint8_t *raw_atk = (const uint8_t[]){
        0x00,0x11,0x22,0x33,0x44,0x55, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x08,0x00,
        0x45,0x00,0x00,0x3c, 0x13,0x37,0x00,0x00, 0x05,0x06,0x00,0x00,
        0x0a,0x00,0x00,0x63, 0x0a,0x00,0x00,0x01,
        0xd4,0x31, 0x01,0xbb, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x00,0x00, 0x50,0x29, 0x20,0x00, 0x00,0x00, 0x00,0x00
    };
    const uint8_t *raw_ok = (const uint8_t[]){
        0x00,0x11,0x22,0x33,0x44,0x55, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x08,0x00,
        0x45,0x00,0x00,0x3c, 0x13,0x37,0x00,0x00, 0x40,0x06,0x00,0x00,
        0x0a,0x00,0x00,0x63, 0x0a,0x00,0x00,0x01,
        0xd4,0x31, 0x01,0xbb, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x00,0x00, 0x50,0x18, 0x72,0x10, 0x00,0x00, 0x00,0x00
    };
    memcpy(pkt_atk, raw_atk, 54);
    memcpy(pkt_ok, raw_ok, 54);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    uint64_t delay_ns = 0;
    int action = 0;
    for (int i = 0; i < 1000000; i++) {
        if ((i & 1) == 0) {
            memcpy(work, pkt_atk, 64);
            chain_step(&chain, work, 64, 2048, &delay_ns, &action);
        } else {
            memcpy(work, pkt_ok, 72);
            chain_step(&chain, work, 72, 2048, &delay_ns, &action);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;

    printf("=== ЕДИНЫЙ КОНВЕЙЕР ЦЕПОЧКИ МОДУЛЕЙ (1 000 000 СМЕШАННЫХ КАДРОВ) ===\n");
    printf("Всего кадров       : %llu за %.4f сек (%.2f млн кадров/сек на 1 ядре)\n",
           (unsigned long long)chain.total_frames, sec, (chain.total_frames / 1e6) / sec);
    printf("Атак в тарпит      : %llu (мгновенно заморожены через TCP Window = 0)\n",
           (unsigned long long)chain.tarpit_replies);
    printf("Чистых в шейпер    : %llu (сглажены энтропия и джиттер IAT)\n",
           (unsigned long long)chain.shaped_clean);

    chain_destroy(&chain);
    free(pkt_atk); free(pkt_ok); free(work);
    return 0;
}
