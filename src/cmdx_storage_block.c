//
//  cmdx_storage_block.c
//  libcmdx
//
//  Created by kejinlu on 2025/11/20.
//

#include "cmdx_storage_block.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include "minilzo.h"
#include "cmdx_endian.h"
#include "cmdx_crypto.h"

// ============================================================
// Internal helper functions
// ============================================================

/**
 * Initialize minilzo library (thread-safe one-time init)
 * @return 0 on success, -1 on failure
 */
static int init_minilzo(void) {
    static int initialized = 0;
    if (initialized) {
        return 0;
    }

    int ret = lzo_init();
    if (ret != LZO_E_OK) {
        fprintf(stderr, "Error: lzo_init() failed (return code: %d)\n", ret);
        return -1;
    }

    initialized = 1;
    return 0;
}

/**
 * Derive V2 key using double RIPEMD-128
 * @param key           Original key
 * @param key_len       Original key length
 * @param derived_key   Output derived key (must be CMDX_HASH128_SIZE bytes)
 * @return 0 on success, -1 on failure
 */
static int derive_v2_key(const uint8_t *key, size_t key_len, uint8_t *derived_key) {
    if (!key || !derived_key) {
        return -1;
    }

    uint8_t temp[CMDX_HASH128_SIZE];
    if (cmdx_ripemd128_hash(key, key_len, temp) != 0) {
        return -1;
    }
    if (cmdx_ripemd128_hash(temp, CMDX_HASH128_SIZE, derived_key) != 0) {
        return -1;
    }

    return 0;
}

/**
 * Verify Adler32 checksum
 * @param data               Data pointer
 * @param len                Data length
 * @param expected_checksum  Expected checksum
 * @return true if checksum matches, false otherwise
 */
static bool verify_adler32(const uint8_t *data, size_t len, uint32_t expected_checksum) {
    uLong ad = adler32(1L, data, (uInt)len);
    return (uint32_t)ad == expected_checksum;
}

// ============================================================
// Public interface
// ============================================================

/*
 * V1/V2 storage block — a single compressed (and possibly encrypted) binary block.
 *
 *    field        size         note
 *    ─────        ────         ────
 *    block_data   src_len      (8-byte header + zlib/LZO body, optionally encrypted)
 */
cmdx_data *cmdx_storage_block_read_v1v2(FILE *fp, cmdx_meta *meta, size_t src_len, size_t dst_len) {
    if (!fp || src_len == 0 || dst_len == 0) {
        return NULL;
    }

    /* ═══════════════════════════════════════════════════════════════════
     * Read compressed data
     * ═══════════════════════════════════════════════════════════════════ */

    uint8_t *block_data_buf = (uint8_t *)malloc(src_len);
    if (!block_data_buf) {
        fprintf(stderr, "Error: failed to allocate compressed data buffer (size: %zu)\n", src_len);
        return NULL;
    }

    size_t bytes_read = fread(block_data_buf, 1, src_len, fp);
    if (bytes_read != src_len) {
        fprintf(stderr, "Error: failed to read compressed data (expected: %zu, got: %zu)\n", src_len, bytes_read);
        free(block_data_buf);
        return NULL;
    }

    /* ═══════════════════════════════════════════════════════════════════
     * Allocate decompression buffer
     * ═══════════════════════════════════════════════════════════════════ */

    uint8_t *decomp_data = (uint8_t *)malloc(dst_len);
    if (!decomp_data) {
        fprintf(stderr, "Error: failed to allocate decompression buffer (size: %zu)\n", dst_len);
        free(block_data_buf);
        return NULL;
    }

    /* ═══════════════════════════════════════════════════════════════════
     * Key derivation (V2: double RIPEMD-128)
     * ═══════════════════════════════════════════════════════════════════ */

    uint8_t *crypto_key = (uint8_t *)meta->crypto_key;
    size_t crypto_key_len = meta->crypto_key_len;
    uint8_t derived_key[CMDX_HASH128_SIZE];

    if (crypto_key && cmdx_is_v2(meta)) {
        if (derive_v2_key(crypto_key, crypto_key_len, derived_key) != 0) {
            fprintf(stderr, "Error: V2 key derivation failed\n");
            free(block_data_buf);
            free(decomp_data);
            return NULL;
        }
        crypto_key = derived_key;
        crypto_key_len = CMDX_HASH128_SIZE;
    }

    /* ═══════════════════════════════════════════════════════════════════
     * Decode: decrypt → verify checksum → decompress
     * ═══════════════════════════════════════════════════════════════════ */

    size_t actual_decomp_size = dst_len;
    int result = cmdx_storage_block_decode(block_data_buf, src_len, crypto_key, crypto_key_len,
                             decomp_data, &actual_decomp_size);

    // Free compressed data buffer
    free(block_data_buf);

    if (result != 0) {
        fprintf(stderr, "Error: failed to decode data block (return code: %d)\n", result);
        free(decomp_data);
        return NULL;
    }

    /* ═══════════════════════════════════════════════════════════════════
     * Wrap result
     * ═══════════════════════════════════════════════════════════════════ */

    cmdx_data *dst_data = malloc(sizeof(cmdx_data));
    if (!dst_data) {
        free(decomp_data);
        return NULL;
    }

    dst_data->data = decomp_data;
    dst_data->length = actual_decomp_size;

    return dst_data;
}

/*
 * V3 storage block — unit-based format.
 *
 *    field       size        endian       note
 *    ─────       ────        ──────       ────
 *    dst_len     4 bytes     big-endian   (decompressed size)
 *    src_len     4 bytes     big-endian   (compressed size)
 *    block_data  src_len                  (delegates to V1/V2 decode)
 */
cmdx_data *cmdx_storage_block_read_v3(FILE *fp, cmdx_meta *meta) {
    if (!fp || !meta) {
        return NULL;
    }

    uint32_t dst_len;
    if (!fread_uint32_be(fp, &dst_len)) {
        if (ferror(fp)) {
            fprintf(stderr, "Error: failed to read destination length\n");
        }
        return NULL;
    }

    uint32_t src_len;
    if (!fread_uint32_be(fp, &src_len)) {
        if (ferror(fp)) {
            fprintf(stderr, "Error: failed to read source length\n");
        }
        return NULL;
    }

    // Validate lengths
    if (dst_len == 0 || src_len == 0) {
        return NULL;
    }

    return cmdx_storage_block_read_v1v2(fp, meta, src_len, dst_len);
}


/*
 * Compressed(data) Block Structure
 *
 *   * header (8 bytes)
 *     - enc_comp_type (1 byte): high 4 bits = encryption type, low 4 bits = compression type
 *     - enc_data_length (1 byte): encrypted data length
 *     - reserved (2 bytes): reserved field
 *     - checksum (4 bytes): Adler32 checksum
 *
 *   * compressed_data (varying)
 *     The compressed payload
 *
 * Encryption type (enc_type):
 *   0x00: No encryption
 *   0x01: Simple encryption
 *   0x02: Salsa20 encryption
 *
 * Compression type (comp_type):
 *   0x00: No compression
 *   0x01: LZO compression
 *   0x02: Zlib compression
 */
cmdx_block_result cmdx_storage_block_decode(uint8_t *input, const size_t input_len,
                 const uint8_t *key, const size_t key_len,
                 uint8_t *output, size_t *output_len) {
    if (!output || !output_len || !input || input_len <= CMDX_BLOCK_HEADER_SIZE) {
        return CMDX_BLOCK_ERR_PARAMS;
    }

    /* ═══════════════════════════════════════════════════════════════════
     * Parse header
     * ═══════════════════════════════════════════════════════════════════ */

    uint8_t enc_comp_type = 0;
    read_uint8(input, input_len, &enc_comp_type);

    uint8_t encrypted_data_len = 0;
    read_uint8(input + 1, input_len - 1, &encrypted_data_len);

    uint16_t reserved;
    read_uint16_be(input + 2, input_len - 2, &reserved);
    (void)reserved;

    uint8_t enc_type = (enc_comp_type & 0xF0) >> 4;
    uint8_t comp_type = enc_comp_type & 0x0F;

    uint32_t checksum = 0;
    read_uint32_be(input + 4, input_len - 4, &checksum);

    uint8_t *block = input + CMDX_BLOCK_HEADER_SIZE;
    size_t block_len = input_len - CMDX_BLOCK_HEADER_SIZE;

    /* ═══════════════════════════════════════════════════════════════════
     * Decryption
     *
     *   If no key was provided but the block is encrypted, derive a
     *   fallback key from the storage block checksum.
     * ═══════════════════════════════════════════════════════════════════ */

    uint8_t fallback_key[CMDX_HASH128_SIZE];
    const uint8_t *effective_key = key;
    size_t effective_key_len = key_len;

    if (enc_type != CMDX_ENC_NONE && (!key || key_len == 0)) {
        uint32_t checksum_be = BSWAP32(checksum);
        if (cmdx_ripemd128_hash((const uint8_t *)&checksum_be, sizeof(checksum_be),
                                fallback_key) != 0) {
            return CMDX_BLOCK_ERR_DECRYPT;
        }
        effective_key = fallback_key;
        effective_key_len = CMDX_HASH128_SIZE;
    }

    switch (enc_type) {
        case CMDX_ENC_NONE:
            break;
        case CMDX_ENC_SIMPLE:
            cmdx_simple_decrypt_inplace(block, encrypted_data_len, effective_key, effective_key_len);
            break;
        case CMDX_ENC_SALSA20: {
            uint8_t *decrypted = cmdx_salsa20_decrypt(block, encrypted_data_len, effective_key, effective_key_len);
            if (!decrypted) {
                return CMDX_BLOCK_ERR_DECRYPT;
            }
            memcpy(block, decrypted, encrypted_data_len);
            free(decrypted);
            break;
        }
        default:
            return CMDX_BLOCK_ERR_ENC_TYPE;
    }

    /* ═══════════════════════════════════════════════════════════════════
     * Checksum verification (if encrypted, checksum is over compressed data)
     * ═══════════════════════════════════════════════════════════════════ */

    bool checksum_for_compressed = (enc_type != CMDX_ENC_NONE);
    if (checksum_for_compressed) {
        if (!verify_adler32(block, block_len, checksum)) {
            return CMDX_BLOCK_ERR_CHECKSUM;
        }
    }

    /* ═══════════════════════════════════════════════════════════════════
     * Decompression
     * ═══════════════════════════════════════════════════════════════════ */

    switch (comp_type) {
    case CMDX_COMP_NONE: {
        if (*output_len < block_len) {
            *output_len = block_len;
            return CMDX_BLOCK_ERR_BUFFER;
        }
        memcpy(output, block, block_len);

        if (!checksum_for_compressed) {
            if (!verify_adler32(output, block_len, checksum)) {
                return CMDX_BLOCK_ERR_CHECKSUM;
            }
        }

        *output_len = block_len;
        return CMDX_BLOCK_OK;
    }
    case CMDX_COMP_LZO: {
        if (init_minilzo() != 0) {
            return CMDX_BLOCK_ERR_LZO_INIT;
        }

        lzo_uint out_len = (lzo_uint)(*output_len);
        int ret = lzo1x_decompress_safe(block, (lzo_uint)block_len,
                                        output, &out_len,
                                        NULL);

        if (ret == LZO_E_OK) {
            if (!checksum_for_compressed) {
                if (!verify_adler32(output, (size_t)out_len, checksum)) {
                    return CMDX_BLOCK_ERR_CHECKSUM;
                }
            }
            *output_len = (size_t)out_len;
            return CMDX_BLOCK_OK;
        } else if (ret == LZO_E_OUTPUT_OVERRUN) {
            *output_len = (size_t)out_len;
            return CMDX_BLOCK_ERR_BUFFER;
        } else {
            fprintf(stderr, "Error: LZO decompression failed (return code: %d)\n", ret);
            return CMDX_BLOCK_ERR_DECOMPRESS;
        }
    }
    case CMDX_COMP_ZLIB: {
        uLong out_len = (uLong)(*output_len);
        int ret = uncompress(output, &out_len, block, (uLong)block_len);

        if (ret == Z_BUF_ERROR) {
            *output_len = (size_t)out_len;
            return CMDX_BLOCK_ERR_BUFFER;
        }
        if (ret != Z_OK) {
            return CMDX_BLOCK_ERR_DECOMPRESS;
        }

        if (!checksum_for_compressed) {
            if (!verify_adler32(output, (size_t)out_len, checksum)) {
                return CMDX_BLOCK_ERR_CHECKSUM;
            }
        }

        *output_len = (size_t)out_len;
        return CMDX_BLOCK_OK;
    }
    default:
        return CMDX_BLOCK_ERR_COMP_TYPE;
    }
}
