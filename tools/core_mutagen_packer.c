#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <x86intrin.h>

#define ZEROMANI_MAGIC 0x494E414D4F52455AULL

typedef struct __attribute__((packed)) {
    uint64_t magic;       // "ZEROMANI"
    uint64_t version;     // 1
    uint64_t payload_len; // размер зашифрованного ядра
    uint64_t nonce;       // аппаратная соль (TSC + urandom)
    uint64_t mac;         // контрольная сумма целостности
} capsule_hdr_t;

static inline uint64_t rotl64(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

// Мутагенный потоковый генератор гаммы (ARX + нелинейная мутация состояния на каждом шаге)
static void mutagen_xor_stream(uint8_t *buf, size_t len, const uint64_t *key, uint64_t nonce) {
    uint64_t s0 = *(key + 0) ^ nonce;
    uint64_t s1 = *(key + 1) ^ rotl64(nonce, 17);
    uint64_t s2 = *(key + 2) ^ rotl64(nonce, 33);
    uint64_t s3 = *(key + 3) ^ 0x9E3779B97F4A7C15ULL;

    size_t i = 0;
    while (i + 8 <= len) {
        s0 += s1; s1 = rotl64(s1, 13) ^ s0;
        s2 += s3; s3 = rotl64(s3, 29) ^ s2;
        uint64_t gamma = (s0 ^ s2) + rotl64(s1 ^ s3, 21);
        s0 ^= rotl64(gamma, 7);

        uint64_t word = 0;
        memcpy(&word, buf + i, 8);
        word ^= gamma;
        memcpy(buf + i, &word, 8);
        i += 8;
    }
    if (i < len) {
        s0 += s1; s1 = rotl64(s1, 13) ^ s0;
        s2 += s3; s3 = rotl64(s3, 29) ^ s2;
        uint64_t gamma = (s0 ^ s2) + rotl64(s1 ^ s3, 21);
        uint8_t *gbytes = (uint8_t *)&gamma;
        for (size_t r = 0; i + r < len; r++) {
            *(buf + i + r) ^= *(gbytes + r);
        }
    }
}

static uint64_t compute_mac(const uint8_t *buf, size_t len, const uint64_t *key, uint64_t nonce) {
    uint64_t h = 0xCBF29CE484222325ULL ^ nonce ^ *(key + 0) ^ *(key + 3);
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)(*(buf + i));
        h *= 0x100000001B3ULL;
        h = rotl64(h, 5);
    }
    return h;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Использование: %s <enc|verify> <входной_файл> <капсула> <файл_ключа>\n", *(argv + 0));
        return 1;
    }
    char mode = **(argv + 1);
    const char *in_path = *(argv + 2);
    const char *cap_path = *(argv + 3);
    const char *key_path = *(argv + 4);

    if (mode == 'e') {
        FILE *fi = fopen(in_path, "rb");
        if (!fi) { perror("fopen input"); return 1; }
        fseek(fi, 0, SEEK_END);
        long fsz = ftell(fi);
        fseek(fi, 0, SEEK_SET);
        if (fsz <= 0) { fclose(fi); return 1; }

        size_t len = (size_t)fsz;
        uint8_t *data = malloc(len);
        if (!data || fread(data, 1, len, fi) != len) { perror("fread"); return 1; }
        fclose(fi);

        uint64_t *key = calloc(4, sizeof(uint64_t));
        int ur = open("/dev/urandom", O_RDONLY);
        if (ur < 0 || read(ur, key, 32) != 32) { perror("urandom"); return 1; }
        uint64_t nonce = __rdtsc();
        uint64_t extra = 0;
        if (read(ur, &extra, 8) == 8) nonce ^= extra;
        close(ur);

        uint64_t mac = compute_mac(data, len, key, nonce);
        mutagen_xor_stream(data, len, key, nonce);

        capsule_hdr_t hdr = {
            .magic = ZEROMANI_MAGIC,
            .version = 1,
            .payload_len = len,
            .nonce = nonce,
            .mac = mac
        };

        FILE *fc = fopen(cap_path, "wb");
        if (!fc) { perror("fopen capsule"); return 1; }
        fwrite(&hdr, sizeof(hdr), 1, fc);
        fwrite(data, 1, len, fc);
        fclose(fc);

        int kfd = open(key_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (kfd < 0 || write(kfd, key, 32) != 32) { perror("write key"); return 1; }
        close(kfd);

        memset(data, 0, len);
        memset(key, 0, 32);
        free(data);
        free(key);

        printf("[МУТАГЕН-ШИФРАТОР] Ядро упаковано в %s (%zu байт) + 256-бит ключ %s\n",
               cap_path, len + sizeof(hdr), key_path);
    } else if (mode == 'v') {
        uint64_t *key = calloc(4, sizeof(uint64_t));
        FILE *fk = fopen(key_path, "rb");
        if (!fk || fread(key, 1, 32, fk) != 32) { perror("read key"); return 1; }
        fclose(fk);

        FILE *fc = fopen(cap_path, "rb");
        if (!fc) { perror("fopen capsule"); return 1; }
        capsule_hdr_t hdr;
        if (fread(&hdr, sizeof(hdr), 1, fc) != 1 || hdr.magic != ZEROMANI_MAGIC) {
            fprintf(stderr, "Ошибка: неверная авторская метка капсулы!\n");
            return 1;
        }
        uint8_t *data = malloc(hdr.payload_len);
        if (!data || fread(data, 1, hdr.payload_len, fc) != hdr.payload_len) { perror("fread cap"); return 1; }
        fclose(fc);

        mutagen_xor_stream(data, hdr.payload_len, key, hdr.nonce);
        uint64_t check_mac = compute_mac(data, hdr.payload_len, key, hdr.nonce);
        if (check_mac != hdr.mac) {
            fprintf(stderr, "ТРЕВОГА: нарушена целостность ядра (MAC mismatch)!\n");
            return 1;
        }

        printf("[ПРОВЕРКА КАПСУЛЫ] Метка: %.8s | Расшифровано в RAM: %llu байт | Целостность MAC: ОК (0x%016llx)\n",
               (char *)&hdr.magic, (unsigned long long)hdr.payload_len, (unsigned long long)check_mac);

        memset(data, 0, hdr.payload_len);
        memset(key, 0, 32);
        free(data);
        free(key);
    }
    return 0;
}
