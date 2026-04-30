#include "salsa20.h"
#include <string.h>

/* Helper macros */

/* 32-bit rotate left */
#define ROTATE(v, c) (((v) << (c)) | ((v) >> (32 - (c))))

/* XOR operation */
#define XOR(v, w) ((v) ^ (w))

/* 32-bit unsigned addition (wraps on overflow) */
#define PLUS(v, w) ((v) + (w))

/* Increment by 1 */
#define PLUSONE(v) (PLUS((v), 1))

/* Convert 32-bit integer to little-endian bytes */
static void u32_to_u8_little(uint8_t *output, uint32_t input)
{
    output[0] = (uint8_t)(input);
    output[1] = (uint8_t)(input >> 8);
    output[2] = (uint8_t)(input >> 16);
    output[3] = (uint8_t)(input >> 24);
}

/* Convert little-endian bytes to 32-bit integer */
static uint32_t u8_to_u32_little(const uint8_t *input)
{
    return ((uint32_t)input[0]) |
           ((uint32_t)input[1] << 8) |
           ((uint32_t)input[2] << 16) |
           ((uint32_t)input[3] << 24);
}

/* Salsa20 core: convert 16 x 32-bit words to 64-byte output */
static void salsa20_word_to_byte(uint8_t output[64], const uint32_t input[16])
{
    uint32_t x[16];
    int i;

    /* Copy input state */
    for (i = 0; i < 16; i++) {
        x[i] = input[i];
    }

    /* 20 rounds (10 double-rounds) */
    for (i = 0; i < 8; i += 2) {
        /* Column round */
        x[4]  = XOR(x[4],  ROTATE(PLUS(x[0],  x[12]), 7));
        x[8]  = XOR(x[8],  ROTATE(PLUS(x[4],  x[0]),  9));
        x[12] = XOR(x[12], ROTATE(PLUS(x[8],  x[4]),  13));
        x[0]  = XOR(x[0],  ROTATE(PLUS(x[12], x[8]),  18));

        x[9]  = XOR(x[9],  ROTATE(PLUS(x[5],  x[1]),  7));
        x[13] = XOR(x[13], ROTATE(PLUS(x[9],  x[5]),  9));
        x[1]  = XOR(x[1],  ROTATE(PLUS(x[13], x[9]),  13));
        x[5]  = XOR(x[5],  ROTATE(PLUS(x[1],  x[13]), 18));

        x[14] = XOR(x[14], ROTATE(PLUS(x[10], x[6]),  7));
        x[2]  = XOR(x[2],  ROTATE(PLUS(x[14], x[10]), 9));
        x[6]  = XOR(x[6],  ROTATE(PLUS(x[2],  x[14]), 13));
        x[10] = XOR(x[10], ROTATE(PLUS(x[6],  x[2]),  18));

        x[3]  = XOR(x[3],  ROTATE(PLUS(x[15], x[11]), 7));
        x[7]  = XOR(x[7],  ROTATE(PLUS(x[3],  x[15]), 9));
        x[11] = XOR(x[11], ROTATE(PLUS(x[7],  x[3]),  13));
        x[15] = XOR(x[15], ROTATE(PLUS(x[11], x[7]),  18));

        /* Row round */
        x[1]  = XOR(x[1],  ROTATE(PLUS(x[0],  x[3]),  7));
        x[2]  = XOR(x[2],  ROTATE(PLUS(x[1],  x[0]),  9));
        x[3]  = XOR(x[3],  ROTATE(PLUS(x[2],  x[1]),  13));
        x[0]  = XOR(x[0],  ROTATE(PLUS(x[3],  x[2]),  18));

        x[6]  = XOR(x[6],  ROTATE(PLUS(x[5],  x[4]),  7));
        x[7]  = XOR(x[7],  ROTATE(PLUS(x[6],  x[5]),  9));
        x[4]  = XOR(x[4],  ROTATE(PLUS(x[7],  x[6]),  13));
        x[5]  = XOR(x[5],  ROTATE(PLUS(x[4],  x[7]),  18));

        x[11] = XOR(x[11], ROTATE(PLUS(x[10], x[9]),  7));
        x[8]  = XOR(x[8],  ROTATE(PLUS(x[11], x[10]), 9));
        x[9]  = XOR(x[9],  ROTATE(PLUS(x[8],  x[11]), 13));
        x[10] = XOR(x[10], ROTATE(PLUS(x[9],  x[8]),  18));

        x[12] = XOR(x[12], ROTATE(PLUS(x[15], x[14]), 7));
        x[13] = XOR(x[13], ROTATE(PLUS(x[12], x[15]), 9));
        x[14] = XOR(x[14], ROTATE(PLUS(x[13], x[12]), 13));
        x[15] = XOR(x[15], ROTATE(PLUS(x[14], x[13]), 18));
    }

    /* Add input state and convert to bytes */
    for (i = 0; i < 16; i++) {
        x[i] = PLUS(x[i], input[i]);
        u32_to_u8_little(output + i * 4, x[i]);
    }
}

/* Constant strings */
static const uint8_t sigma[16] = "expand 32-byte k";  /* Used for 256-bit key */
static const uint8_t tau[16]   = "expand 16-byte k";  /* Used for 128-bit key */

void salsa20_key_setup(salsa20_context *ctx, const uint8_t *key, size_t kbits)
{
    const uint8_t *constants;
    size_t k_offset;

    /* Select constants and key offset based on key size */
    if (kbits == 256) {
        constants = sigma;
        k_offset = 16;
    } else {
        /* 128-bit key */
        constants = tau;
        k_offset = 0;
    }

    /* Set first half of key (input[1-4]) */
    ctx->input[1] = u8_to_u32_little(key + 0);
    ctx->input[2] = u8_to_u32_little(key + 4);
    ctx->input[3] = u8_to_u32_little(key + 8);
    ctx->input[4] = u8_to_u32_little(key + 12);

    /* Set second half of key (input[11-14]) */
    /* For 256-bit key use the last 16 bytes; 128-bit key reuses the first 16 bytes */
    ctx->input[11] = u8_to_u32_little(key + k_offset + 0);
    ctx->input[12] = u8_to_u32_little(key + k_offset + 4);
    ctx->input[13] = u8_to_u32_little(key + k_offset + 8);
    ctx->input[14] = u8_to_u32_little(key + k_offset + 12);

    /* Set constants (input[0, 5, 10, 15]) */
    ctx->input[0]  = u8_to_u32_little(constants + 0);
    ctx->input[5]  = u8_to_u32_little(constants + 4);
    ctx->input[10] = u8_to_u32_little(constants + 8);
    ctx->input[15] = u8_to_u32_little(constants + 12);
}

void salsa20_iv_setup(salsa20_context *ctx, const uint8_t *iv)
{
    /* Set IV/Nonce (input[6-7]) */
    ctx->input[6] = u8_to_u32_little(iv + 0);
    ctx->input[7] = u8_to_u32_little(iv + 4);

    /* Initialize counter to 0 (input[8-9]) */
    ctx->input[8] = 0;
    ctx->input[9] = 0;
}

void salsa20_encrypt_bytes(salsa20_context *ctx, const uint8_t *m, uint8_t *c, size_t bytes)
{
    uint8_t output[64];
    size_t i;

    if (bytes == 0) {
        return;
    }

    while (1) {
        /* Generate 64-byte keystream block */
        salsa20_word_to_byte(output, ctx->input);

        /* Increment 64-bit counter */
        ctx->input[8] = PLUSONE(ctx->input[8]);
        if (ctx->input[8] == 0) {
            /* Low 32 bits overflowed, increment high 32 bits */
            ctx->input[9] = PLUSONE(ctx->input[9]);
            /* Note: each nonce can encrypt up to 2^70 bytes; caller must handle overflow */
        }

        if (bytes <= 64) {
            /* Handle final partial block (< 64 bytes) */
            for (i = 0; i < bytes; i++) {
                c[i] = m[i] ^ output[i];
            }
            return;
        }

        /* Handle full 64-byte block */
        for (i = 0; i < 64; i++) {
            c[i] = m[i] ^ output[i];
        }

        bytes -= 64;
        m += 64;
        c += 64;
    }
}

void salsa20_decrypt_bytes(salsa20_context *ctx, const uint8_t *c, uint8_t *m, size_t bytes)
{
    /* Salsa20 is a stream cipher; encrypt and decrypt are identical (both XOR) */
    salsa20_encrypt_bytes(ctx, c, m, bytes);
}
