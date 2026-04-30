//
//  cmdx_storage_block.h
//  libcmdx
//
//  Created by kejinlu on 2025/11/20.
//

#ifndef cmdx_storage_block_h
#define cmdx_storage_block_h

#include <stdio.h>
#include "cmdx_meta.h"
#include "cmdx_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// Storage block constants
// ============================================================

#define CMDX_BLOCK_HEADER_SIZE 8

typedef enum {
    CMDX_ENC_NONE    = 0x00,
    CMDX_ENC_SIMPLE  = 0x01,
    CMDX_ENC_SALSA20 = 0x02
} cmdx_encryption_type;

typedef enum {
    CMDX_COMP_NONE = 0x00,
    CMDX_COMP_LZO  = 0x01,
    CMDX_COMP_ZLIB = 0x02
} cmdx_compression_type;

typedef enum {
    CMDX_BLOCK_OK              =  0,
    CMDX_BLOCK_ERR_PARAMS      = -1,
    CMDX_BLOCK_ERR_ENC_TYPE    = -2,
    CMDX_BLOCK_ERR_COMP_TYPE   = -3,
    CMDX_BLOCK_ERR_CHECKSUM    = -4,
    CMDX_BLOCK_ERR_BUFFER      = -5,
    CMDX_BLOCK_ERR_DECOMPRESS  = -6,
    CMDX_BLOCK_ERR_DECRYPT     = -7,
    CMDX_BLOCK_ERR_LZO_INIT    = -8
} cmdx_block_result;

// ============================================================
// Public interface
// ============================================================

cmdx_data *cmdx_storage_block_read_v1v2(FILE *fp, cmdx_meta *meta, size_t src_len, size_t dst_len);
cmdx_data *cmdx_storage_block_read_v3(FILE *fp, cmdx_meta *meta);

cmdx_block_result cmdx_storage_block_decode(uint8_t *input, const size_t input_len,
                     const uint8_t *key, const size_t key_len,
                     uint8_t *output, size_t *output_len);
#ifdef __cplusplus
}
#endif

#endif /* cmdx_storage_block_h */
