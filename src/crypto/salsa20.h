#ifndef salsa20_h
#define salsa20_h

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t input[16];
} salsa20_context;

/**
 * Initialize Salsa20 key
 * @param ctx     Salsa20 context
 * @param key     Key data
 * @param kbits   Key length in bits (128 or 256)
 */
void salsa20_key_setup(salsa20_context *ctx, const uint8_t *key, size_t kbits);

/**
 * Set initialization vector (IV/Nonce)
 * @param ctx  Salsa20 context
 * @param iv   8-byte initialization vector
 */
void salsa20_iv_setup(salsa20_context *ctx, const uint8_t *iv);

/**
 * Encrypt data
 * @param ctx     Salsa20 context
 * @param m       Plaintext input
 * @param c       Ciphertext output
 * @param bytes   Data length
 */
void salsa20_encrypt_bytes(salsa20_context *ctx, const uint8_t *m, uint8_t *c, size_t bytes);

/**
 * Decrypt data (same operation as encrypt for stream ciphers)
 * @param ctx     Salsa20 context
 * @param c       Ciphertext input
 * @param m       Plaintext output
 * @param bytes   Data length
 */
void salsa20_decrypt_bytes(salsa20_context *ctx, const uint8_t *c, uint8_t *m, size_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* salsa20_h */
