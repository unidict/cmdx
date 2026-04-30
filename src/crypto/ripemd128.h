/*
 * RIPEMD-128 implementation
 * Based on the original implementation by Antoon Bosselaers, ESAT-COSIC
 * Refactored with streaming API support
 */

#ifndef ripemd128_h
#define ripemd128_h

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIPEMD128_DIGEST_SIZE 16
#define RIPEMD128_BLOCK_SIZE  64

typedef struct {
    uint32_t h[4];       /* Current hash state */
    uint64_t length;     /* Total number of bits processed */
    uint8_t  buf[64];    /* Input buffer */
    unsigned bufpos;     /* Number of bytes currently in the buffer */
} ripemd128_state;

/*
 * Initialize the hash state
 * Returns 0 on success, non-zero on error
 */
int ripemd128_init(ripemd128_state **state);

/*
 * Process input data
 * Can be called multiple times for streaming
 * Returns 0 on success, non-zero on error
 */
int ripemd128_update(ripemd128_state *state, const uint8_t *data, size_t len);

/*
 * Finalize and output the hash digest
 * Does not modify the state (makes internal copy for padding)
 * Returns 0 on success, non-zero on error
 */
int ripemd128_digest(const ripemd128_state *state, uint8_t digest[RIPEMD128_DIGEST_SIZE]);

/*
 * Free hash state
 * Returns 0 on success
 */
int ripemd128_destroy(ripemd128_state *state);

/*
 * Convenience function:  hash data in one call
 * Returns 0 on success, non-zero on error
 */
int ripemd128_hash(const uint8_t *data, size_t len, uint8_t digest[RIPEMD128_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ripemd128_h */
