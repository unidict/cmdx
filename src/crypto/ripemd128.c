/*
 * RIPEMD-128 implementation
 *
 * Original implementation by Antoon Bosselaers, ESAT-COSIC (1996)
 * Copyright (c) Katholieke Universiteit Leuven 1996, All Rights Reserved
 *
 * Refactored with streaming API and improved structure
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ripemd128.h"

/* Error codes */
#define ERR_NULL   1
#define ERR_MEMORY 2

/* Cyclic left-shift */
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* Load 32-bit word in little-endian */
#define LOAD_U32_LITTLE(p) \
    (((uint32_t)(p)[0]) | ((uint32_t)(p)[1] << 8) | \
     ((uint32_t)(p)[2] << 16) | ((uint32_t)(p)[3] << 24))

/* Store 32-bit word in little-endian */
#define STORE_U32_LITTLE(p, v) do { \
    (p)[0] = (uint8_t)((v));        \
    (p)[1] = (uint8_t)((v) >> 8);   \
    (p)[2] = (uint8_t)((v) >> 16);  \
    (p)[3] = (uint8_t)((v) >> 24);  \
} while(0)

/* Store 64-bit word in little-endian */
#define STORE_U64_LITTLE(p, v) do { \
    (p)[0] = (uint8_t)((v));        \
    (p)[1] = (uint8_t)((v) >> 8);   \
    (p)[2] = (uint8_t)((v) >> 16);  \
    (p)[3] = (uint8_t)((v) >> 24);  \
    (p)[4] = (uint8_t)((v) >> 32);  \
    (p)[5] = (uint8_t)((v) >> 40);  \
    (p)[6] = (uint8_t)((v) >> 48);  \
    (p)[7] = (uint8_t)((v) >> 56);  \
} while(0)

/* Boolean functions */
#define F(x, y, z) ((x) ^ (y) ^ (z))
#define G(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define H(x, y, z) ((z) ^ ((x) | ~(y)))
#define I(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))

/* Round constants - left line */
#define K0 0x00000000u
#define K1 0x5A827999u
#define K2 0x6ED9EBA1u
#define K3 0x8F1BBCDCu

/* Round constants - right line */
#define K5 0x50A28BE6u
#define K6 0x5C4DD124u
#define K7 0x6D703EF3u
#define K9 0x00000000u

/* Round operations - left line */
#define FF(a, b, c, d, x, s) { (a) += F((b), (c), (d)) + (x) + K0; (a) = ROL((a), (s)); }
#define GG(a, b, c, d, x, s) { (a) += G((b), (c), (d)) + (x) + K1; (a) = ROL((a), (s)); }
#define HH(a, b, c, d, x, s) { (a) += H((b), (c), (d)) + (x) + K2; (a) = ROL((a), (s)); }
#define II(a, b, c, d, x, s) { (a) += I((b), (c), (d)) + (x) + K3; (a) = ROL((a), (s)); }

/* Round operations - right line (parallel) */
#define FFF(a, b, c, d, x, s) { (a) += F((b), (c), (d)) + (x) + K9; (a) = ROL((a), (s)); }
#define GGG(a, b, c, d, x, s) { (a) += G((b), (c), (d)) + (x) + K7; (a) = ROL((a), (s)); }
#define HHH(a, b, c, d, x, s) { (a) += H((b), (c), (d)) + (x) + K6; (a) = ROL((a), (s)); }
#define III(a, b, c, d, x, s) { (a) += I((b), (c), (d)) + (x) + K5; (a) = ROL((a), (s)); }

/* Initial hash values */
static const uint32_t initial_h[4] = {
    0x67452301u,
    0xEFCDAB89u,
    0x98BADCFEu,
    0x10325476u
};

/*
 * The RIPEMD-128 compression function
 */
static void ripemd128_compress(ripemd128_state *self)
{
    uint32_t aa, bb, cc, dd;       /* left line */
    uint32_t aaa, bbb, ccc, ddd;   /* right line */
    uint32_t T;
    uint32_t X[16];
    unsigned i;

    /* Load message block as little-endian 32-bit words */
    for (i = 0; i < 16; i++) {
        X[i] = LOAD_U32_LITTLE(&self->buf[i * 4]);
    }

    /* Initialize working variables */
    aa = aaa = self->h[0];
    bb = bbb = self->h[1];
    cc = ccc = self->h[2];
    dd = ddd = self->h[3];

    /* Round 1 - left line */
    FF(aa, bb, cc, dd, X[ 0], 11);
    FF(dd, aa, bb, cc, X[ 1], 14);
    FF(cc, dd, aa, bb, X[ 2], 15);
    FF(bb, cc, dd, aa, X[ 3], 12);
    FF(aa, bb, cc, dd, X[ 4],  5);
    FF(dd, aa, bb, cc, X[ 5],  8);
    FF(cc, dd, aa, bb, X[ 6],  7);
    FF(bb, cc, dd, aa, X[ 7],  9);
    FF(aa, bb, cc, dd, X[ 8], 11);
    FF(dd, aa, bb, cc, X[ 9], 13);
    FF(cc, dd, aa, bb, X[10], 14);
    FF(bb, cc, dd, aa, X[11], 15);
    FF(aa, bb, cc, dd, X[12],  6);
    FF(dd, aa, bb, cc, X[13],  7);
    FF(cc, dd, aa, bb, X[14],  9);
    FF(bb, cc, dd, aa, X[15],  8);

    /* Round 2 - left line */
    GG(aa, bb, cc, dd, X[ 7],  7);
    GG(dd, aa, bb, cc, X[ 4],  6);
    GG(cc, dd, aa, bb, X[13],  8);
    GG(bb, cc, dd, aa, X[ 1], 13);
    GG(aa, bb, cc, dd, X[10], 11);
    GG(dd, aa, bb, cc, X[ 6],  9);
    GG(cc, dd, aa, bb, X[15],  7);
    GG(bb, cc, dd, aa, X[ 3], 15);
    GG(aa, bb, cc, dd, X[12],  7);
    GG(dd, aa, bb, cc, X[ 0], 12);
    GG(cc, dd, aa, bb, X[ 9], 15);
    GG(bb, cc, dd, aa, X[ 5],  9);
    GG(aa, bb, cc, dd, X[ 2], 11);
    GG(dd, aa, bb, cc, X[14],  7);
    GG(cc, dd, aa, bb, X[11], 13);
    GG(bb, cc, dd, aa, X[ 8], 12);

    /* Round 3 - left line */
    HH(aa, bb, cc, dd, X[ 3], 11);
    HH(dd, aa, bb, cc, X[10], 13);
    HH(cc, dd, aa, bb, X[14],  6);
    HH(bb, cc, dd, aa, X[ 4],  7);
    HH(aa, bb, cc, dd, X[ 9], 14);
    HH(dd, aa, bb, cc, X[15],  9);
    HH(cc, dd, aa, bb, X[ 8], 13);
    HH(bb, cc, dd, aa, X[ 1], 15);
    HH(aa, bb, cc, dd, X[ 2], 14);
    HH(dd, aa, bb, cc, X[ 7],  8);
    HH(cc, dd, aa, bb, X[ 0], 13);
    HH(bb, cc, dd, aa, X[ 6],  6);
    HH(aa, bb, cc, dd, X[13],  5);
    HH(dd, aa, bb, cc, X[11], 12);
    HH(cc, dd, aa, bb, X[ 5],  7);
    HH(bb, cc, dd, aa, X[12],  5);

    /* Round 4 - left line */
    II(aa, bb, cc, dd, X[ 1], 11);
    II(dd, aa, bb, cc, X[ 9], 12);
    II(cc, dd, aa, bb, X[11], 14);
    II(bb, cc, dd, aa, X[10], 15);
    II(aa, bb, cc, dd, X[ 0], 14);
    II(dd, aa, bb, cc, X[ 8], 15);
    II(cc, dd, aa, bb, X[12],  9);
    II(bb, cc, dd, aa, X[ 4],  8);
    II(aa, bb, cc, dd, X[13],  9);
    II(dd, aa, bb, cc, X[ 3], 14);
    II(cc, dd, aa, bb, X[ 7],  5);
    II(bb, cc, dd, aa, X[15],  6);
    II(aa, bb, cc, dd, X[14],  8);
    II(dd, aa, bb, cc, X[ 5],  6);
    II(cc, dd, aa, bb, X[ 6],  5);
    II(bb, cc, dd, aa, X[ 2], 12);

    /* Parallel round 1 - right line */
    III(aaa, bbb, ccc, ddd, X[ 5],  8);
    III(ddd, aaa, bbb, ccc, X[14],  9);
    III(ccc, ddd, aaa, bbb, X[ 7],  9);
    III(bbb, ccc, ddd, aaa, X[ 0], 11);
    III(aaa, bbb, ccc, ddd, X[ 9], 13);
    III(ddd, aaa, bbb, ccc, X[ 2], 15);
    III(ccc, ddd, aaa, bbb, X[11], 15);
    III(bbb, ccc, ddd, aaa, X[ 4],  5);
    III(aaa, bbb, ccc, ddd, X[13],  7);
    III(ddd, aaa, bbb, ccc, X[ 6],  7);
    III(ccc, ddd, aaa, bbb, X[15],  8);
    III(bbb, ccc, ddd, aaa, X[ 8], 11);
    III(aaa, bbb, ccc, ddd, X[ 1], 14);
    III(ddd, aaa, bbb, ccc, X[10], 14);
    III(ccc, ddd, aaa, bbb, X[ 3], 12);
    III(bbb, ccc, ddd, aaa, X[12],  6);

    /* Parallel round 2 - right line */
    HHH(aaa, bbb, ccc, ddd, X[ 6],  9);
    HHH(ddd, aaa, bbb, ccc, X[11], 13);
    HHH(ccc, ddd, aaa, bbb, X[ 3], 15);
    HHH(bbb, ccc, ddd, aaa, X[ 7],  7);
    HHH(aaa, bbb, ccc, ddd, X[ 0], 12);
    HHH(ddd, aaa, bbb, ccc, X[13],  8);
    HHH(ccc, ddd, aaa, bbb, X[ 5],  9);
    HHH(bbb, ccc, ddd, aaa, X[10], 11);
    HHH(aaa, bbb, ccc, ddd, X[14],  7);
    HHH(ddd, aaa, bbb, ccc, X[15],  7);
    HHH(ccc, ddd, aaa, bbb, X[ 8], 12);
    HHH(bbb, ccc, ddd, aaa, X[12],  7);
    HHH(aaa, bbb, ccc, ddd, X[ 4],  6);
    HHH(ddd, aaa, bbb, ccc, X[ 9], 15);
    HHH(ccc, ddd, aaa, bbb, X[ 1], 13);
    HHH(bbb, ccc, ddd, aaa, X[ 2], 11);

    /* Parallel round 3 - right line */
    GGG(aaa, bbb, ccc, ddd, X[15],  9);
    GGG(ddd, aaa, bbb, ccc, X[ 5],  7);
    GGG(ccc, ddd, aaa, bbb, X[ 1], 15);
    GGG(bbb, ccc, ddd, aaa, X[ 3], 11);
    GGG(aaa, bbb, ccc, ddd, X[ 7],  8);
    GGG(ddd, aaa, bbb, ccc, X[14],  6);
    GGG(ccc, ddd, aaa, bbb, X[ 6],  6);
    GGG(bbb, ccc, ddd, aaa, X[ 9], 14);
    GGG(aaa, bbb, ccc, ddd, X[11], 12);
    GGG(ddd, aaa, bbb, ccc, X[ 8], 13);
    GGG(ccc, ddd, aaa, bbb, X[12],  5);
    GGG(bbb, ccc, ddd, aaa, X[ 2], 14);
    GGG(aaa, bbb, ccc, ddd, X[10], 13);
    GGG(ddd, aaa, bbb, ccc, X[ 0], 13);
    GGG(ccc, ddd, aaa, bbb, X[ 4],  7);
    GGG(bbb, ccc, ddd, aaa, X[13],  5);

    /* Parallel round 4 - right line */
    FFF(aaa, bbb, ccc, ddd, X[ 8], 15);
    FFF(ddd, aaa, bbb, ccc, X[ 6],  5);
    FFF(ccc, ddd, aaa, bbb, X[ 4],  8);
    FFF(bbb, ccc, ddd, aaa, X[ 1], 11);
    FFF(aaa, bbb, ccc, ddd, X[ 3], 14);
    FFF(ddd, aaa, bbb, ccc, X[11], 14);
    FFF(ccc, ddd, aaa, bbb, X[15],  6);
    FFF(bbb, ccc, ddd, aaa, X[ 0], 14);
    FFF(aaa, bbb, ccc, ddd, X[ 5],  6);
    FFF(ddd, aaa, bbb, ccc, X[12],  9);
    FFF(ccc, ddd, aaa, bbb, X[ 2], 12);
    FFF(bbb, ccc, ddd, aaa, X[13],  9);
    FFF(aaa, bbb, ccc, ddd, X[ 9], 12);
    FFF(ddd, aaa, bbb, ccc, X[ 7],  5);
    FFF(ccc, ddd, aaa, bbb, X[10], 15);
    FFF(bbb, ccc, ddd, aaa, X[14],  8);

    /* Final addition - combine left and right lines */
    T = self->h[1] + cc + ddd;
    self->h[1] = self->h[2] + dd + aaa;
    self->h[2] = self->h[3] + aa + bbb;
    self->h[3] = self->h[0] + bb + ccc;
    self->h[0] = T;

    /* Clear sensitive data */
    T = aa = bb = cc = dd = aaa = bbb = ccc = ddd = 0;
    memset(X, 0, sizeof(X));
    memset(self->buf, 0, sizeof(self->buf));
    self->bufpos = 0;
}

int ripemd128_init(ripemd128_state **state)
{
    ripemd128_state *s;

    if (NULL == state) {
        return ERR_NULL;
    }

    *state = s = (ripemd128_state *)calloc(1, sizeof(ripemd128_state));
    if (NULL == s) {
        return ERR_MEMORY;
    }

    memcpy(s->h, initial_h, sizeof(initial_h));
    s->length = 0;
    s->bufpos = 0;

    return 0;
}

int ripemd128_destroy(ripemd128_state *state)
{
    if (state) {
        memset(state, 0, sizeof(ripemd128_state));
        free(state);
    }
    return 0;
}

int ripemd128_update(ripemd128_state *state, const uint8_t *data, size_t len)
{
    unsigned bytes_needed;

    if (NULL == state || NULL == data) {
        return ERR_NULL;
    }

    while (len > 0) {
        bytes_needed = 64 - state->bufpos;

        if (len >= bytes_needed) {
            memcpy(&state->buf[state->bufpos], data, bytes_needed);
            state->bufpos += bytes_needed;
            state->length += (uint64_t)bytes_needed * 8;
            data += bytes_needed;
            len -= bytes_needed;
            ripemd128_compress(state);
        } else {
            memcpy(&state->buf[state->bufpos], data, len);
            state->bufpos += (unsigned)len;
            state->length += (uint64_t)len * 8;
            return 0;
        }
    }

    return 0;
}

int ripemd128_digest(const ripemd128_state *state, uint8_t digest[RIPEMD128_DIGEST_SIZE])
{
    ripemd128_state tmp;
    unsigned i;

    if (NULL == state || NULL == digest) {
        return ERR_NULL;
    }

    /* Work on a copy */
    tmp = *state;

    /* Append padding bit (0x80) */
    tmp.buf[tmp.bufpos++] = 0x80;

    /* If not enough room for 64-bit length, pad to 64 and compress */
    if (tmp.bufpos > 56) {
        while (tmp.bufpos < 64) {
            tmp.buf[tmp.bufpos++] = 0x00;
        }
        ripemd128_compress(&tmp);
    }

    /* Pad to 56 bytes */
    while (tmp.bufpos < 56) {
        tmp.buf[tmp.bufpos++] = 0x00;
    }

    /* Append original length in bits as 64-bit little-endian */
    STORE_U64_LITTLE(&tmp.buf[56], tmp.length);
    tmp.bufpos = 64;
    ripemd128_compress(&tmp);

    /* Output digest in little-endian */
    for (i = 0; i < 4; i++) {
        STORE_U32_LITTLE(&digest[i * 4], tmp.h[i]);
    }

    /* Clear sensitive data */
    memset(&tmp, 0, sizeof(tmp));

    return 0;
}

int ripemd128_hash(const uint8_t *data, size_t len, uint8_t digest[RIPEMD128_DIGEST_SIZE])
{
    ripemd128_state *state = NULL;
    int ret;

    ret = ripemd128_init(&state);
    if (ret != 0) return ret;

    ret = ripemd128_update(state, data, len);
    if (ret != 0) {
        ripemd128_destroy(state);
        return ret;
    }

    ret = ripemd128_digest(state, digest);
    ripemd128_destroy(state);

    return ret;
}
