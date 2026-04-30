//
//  cmdx_crypto.h
//  libcmdx
//
//  Created by kejinlu on 2025/11/20.
//

#ifndef cmdx_crypto_h
#define cmdx_crypto_h

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CMDX_HASH128_SIZE 16

void cmdx_simple_decrypt_inplace(uint8_t *data, const size_t data_len,
                            const uint8_t *key, const size_t key_len);

uint8_t *cmdx_salsa20_decrypt(const uint8_t *data, const size_t data_length,
                         const uint8_t *key, const size_t key_len);

int cmdx_ripemd128_hash(const uint8_t *input, size_t input_len,
                   uint8_t output[CMDX_HASH128_SIZE]);

int cmdx_fast128_hash(uint8_t *input, size_t input_len,
                      uint8_t output[CMDX_HASH128_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* cmdx_crypto_h */
