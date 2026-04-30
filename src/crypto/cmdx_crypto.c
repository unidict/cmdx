//
//  cmdx_crypto.c
//  libcmdx
//
//  Created by kejinlu on 2025/11/20.
//

#include "cmdx_crypto.h"
#include "ripemd128.h"
#include "salsa20.h"
#include <stdlib.h>
#include <string.h>

// ============================================================
// Simple in-place decrypt
// ============================================================

void cmdx_simple_decrypt_inplace(uint8_t *data, const size_t data_len,
                            const uint8_t *key, const size_t key_len) {
    if (!data || !key || data_len == 0 || key_len == 0) {
        return;
    }
    uint8_t *b = data;
    uint8_t previous = 0x36;
    for (size_t i = 0; i < data_len; ++i) {
        uint8_t t = (uint8_t)(((b[i] >> 4) | (b[i] << 4)) & 0xff);
        t = t ^ previous ^ ((uint8_t)(i & 0xff)) ^ key[i % key_len];
        previous = b[i];
        b[i] = t;
    }
}

// ============================================================
// Salsa20 decrypt
// ============================================================

uint8_t *cmdx_salsa20_decrypt(const uint8_t *data, const size_t data_length,
                         const uint8_t *key, const size_t key_len) {
    if (!data || !key || data_length == 0 || key_len == 0) {
        return NULL;
    }
    static const uint8_t zero_nonce[8] = {0};
    salsa20_context ctx_dec;
    salsa20_key_setup(&ctx_dec, key, key_len * 8);
    salsa20_iv_setup(&ctx_dec, zero_nonce);
    uint8_t *decrypted = malloc(data_length);
    if (!decrypted) {
        return NULL;
    }
    salsa20_decrypt_bytes(&ctx_dec, data, decrypted, data_length);
    return decrypted;
}

// ============================================================
// RIPEMD-128
// ============================================================

int cmdx_ripemd128_hash(const uint8_t *input, size_t input_len,
                   uint8_t output[CMDX_HASH128_SIZE]) {
    return ripemd128_hash(input, input_len, output);
}

// ============================================================
// XXH64 (extracted from xxHash by Yann Collet)
// ============================================================

#define XXH_PRIME64_1 0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3 0x165667B19E3779F9ULL
#define XXH_PRIME64_4 0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5 0x27D4EB2F165667C5ULL

static inline uint64_t xxh_read64(const uint8_t *p) {
    return (uint64_t)p[0]       | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline uint32_t xxh_read32(const uint8_t *p) {
    return (uint32_t)p[0]       | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t xxh_rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

static inline uint64_t xxh64_round(uint64_t acc, uint64_t input) {
    acc += input * XXH_PRIME64_2;
    acc = xxh_rotl64(acc, 31);
    acc *= XXH_PRIME64_1;
    return acc;
}

static inline uint64_t xxh64_merge_round(uint64_t acc, uint64_t val) {
    val = xxh64_round(0, val);
    acc ^= val;
    acc = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
    return acc;
}

static inline uint64_t xxh64_avalanche(uint64_t hash) {
    hash ^= hash >> 33;
    hash *= XXH_PRIME64_2;
    hash ^= hash >> 29;
    hash *= XXH_PRIME64_3;
    hash ^= hash >> 32;
    return hash;
}

static uint64_t xxh64(const void *input, size_t len, uint64_t seed) {
    const uint8_t *p = (const uint8_t *)input;
    const uint8_t *end = p + len;
    uint64_t h64;

    if (len >= 32) {
        uint64_t acc[4] = {
            seed + XXH_PRIME64_1 + XXH_PRIME64_2,
            seed + XXH_PRIME64_2,
            seed + 0,
            seed - XXH_PRIME64_1,
        };
        const uint8_t *limit = end - 32;
        do {
            acc[0] = xxh64_round(acc[0], xxh_read64(p)); p += 8;
            acc[1] = xxh64_round(acc[1], xxh_read64(p)); p += 8;
            acc[2] = xxh64_round(acc[2], xxh_read64(p)); p += 8;
            acc[3] = xxh64_round(acc[3], xxh_read64(p)); p += 8;
        } while (p <= limit);

        h64 = xxh_rotl64(acc[0], 1) + xxh_rotl64(acc[1], 7) +
              xxh_rotl64(acc[2], 12) + xxh_rotl64(acc[3], 18);
        h64 = xxh64_merge_round(h64, acc[0]);
        h64 = xxh64_merge_round(h64, acc[1]);
        h64 = xxh64_merge_round(h64, acc[2]);
        h64 = xxh64_merge_round(h64, acc[3]);
    } else {
        h64 = seed + XXH_PRIME64_5;
    }

    h64 += (uint64_t)len;

    while (p + 8 <= end) {
        uint64_t k1 = xxh64_round(0, xxh_read64(p));
        p += 8;
        h64 ^= k1;
        h64 = xxh_rotl64(h64, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
    }

    if (p + 4 <= end) {
        h64 ^= (uint64_t)xxh_read32(p) * XXH_PRIME64_1;
        p += 4;
        h64 = xxh_rotl64(h64, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
    }

    while (p < end) {
        h64 ^= (*p++) * XXH_PRIME64_5;
        h64 = xxh_rotl64(h64, 11) * XXH_PRIME64_1;
    }

    return xxh64_avalanche(h64);
}

static inline void write_be64(uint64_t value, uint8_t *dest) {
    dest[0] = (uint8_t)((value >> 56) & 0xFF);
    dest[1] = (uint8_t)((value >> 48) & 0xFF);
    dest[2] = (uint8_t)((value >> 40) & 0xFF);
    dest[3] = (uint8_t)((value >> 32) & 0xFF);
    dest[4] = (uint8_t)((value >> 24) & 0xFF);
    dest[5] = (uint8_t)((value >> 16) & 0xFF);
    dest[6] = (uint8_t)((value >> 8) & 0xFF);
    dest[7] = (uint8_t)(value & 0xFF);
}

// ============================================================
// Fast hash 128
// ============================================================

int cmdx_fast128_hash(uint8_t *input, size_t input_len, uint8_t *output) {
    if (!input || !output) {
        return -1;
    }
    if (input_len == 0) {
        return -2;
    }

    const size_t first_part_len = (input_len + 1) / 2;
    const size_t second_part_len = input_len > first_part_len ? (input_len - first_part_len) : 0;

    uint64_t hash1 = xxh64(input, first_part_len, 0);
    write_be64(hash1, output);

    if (second_part_len > 0) {
        uint64_t hash2 = xxh64(input + first_part_len, second_part_len, 0);
        write_be64(hash2, output + 8);
    } else {
        memset(output + 8, 0, 8);
    }

    return 0;
}
