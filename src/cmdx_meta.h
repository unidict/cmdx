//
//  cmdx_meta.h
//  libcmdx
//
//  Created by kejinlu on 2025/11/17.
//

#ifndef cmdx_meta_h
#define cmdx_meta_h

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Key block index encryption type (bitmask flags).
 * Can be combined with bitwise OR, e.g. HEADER | DATA = ALL.
 */
typedef enum {
    CMDX_KEY_BLOCK_INDEX_ENCRYPTION_TYPE_NONE = 0,   // No encryption
    CMDX_KEY_BLOCK_INDEX_ENCRYPTION_TYPE_INFO = 1,   // Header encrypted
    CMDX_KEY_BLOCK_INDEX_ENCRYPTION_TYPE_DATA = 2,   // Data encrypted
    CMDX_KEY_BLOCK_INDEX_ENCRYPTION_TYPE_ALL = 3      // All encrypted
} ud_mdict_key_block_index_encryption_type;

/**
 * MDict file encoding type.
 */
typedef enum {
    CMDX_ENCODING_UTF8 = 0,
    CMDX_ENCODING_UTF16 = 1,
    CMDX_ENCODING_BIG5 = 2,
    CMDX_ENCODING_GBK = 3,
    CMDX_ENCODING_GB2312 = 4,
    CMDX_ENCODING_GB18030 = 5,
    CMDX_ENCODING_UNKNOWN = -1
} cmdx_encoding;

/**
 * MDict content format.
 */
typedef enum {
    CMDX_FORMAT_HTML = 0,
    CMDX_FORMAT_TEXT = 1,
    CMDX_FORMAT_NONE = -1
} cmdx_format;

/**
 * MDict version number.
 */
typedef enum {
    CMDX_V1 = 1,
    CMDX_V2 = 2,
    CMDX_V3 = 3
} cmdx_version;

/**
 * MDict file header metadata.
 * Fields are ordered by size for memory alignment.
 */
typedef struct {
    char *creation_date;
    char *description;
    char *title;
    char *style_sheet;
    char *register_by;
    char *reg_code;
    char *default_sorting_locale;

    uint8_t *crypto_key;
    char *uuid;

    size_t crypto_key_len;

    cmdx_version version;
    cmdx_encoding encoding;
    cmdx_format format;

    uint8_t encrypted;

    bool compact;
    bool compat;
    bool key_case_sensitive;
    bool strip_key;
    bool left2right;
    bool is_utf16;

    bool is_mdx;
} cmdx_meta;

cmdx_meta *cmdx_meta_read(FILE *file);

void cmdx_meta_free(cmdx_meta *meta);

const char* cmdx_encoding_name(cmdx_encoding encoding);

// =============================================================================
// Convenience check functions (inline)
// =============================================================================

static inline bool is_key_block_index_info_encrypted(cmdx_meta *meta) {
    if (!meta)
        return false;
    return (meta->encrypted &
            CMDX_KEY_BLOCK_INDEX_ENCRYPTION_TYPE_INFO) != 0;
}

static inline bool is_key_block_index_data_encrypted(cmdx_meta *meta) {
    if (!meta)
        return false;
    return (meta->encrypted & CMDX_KEY_BLOCK_INDEX_ENCRYPTION_TYPE_DATA) !=
           0;
}

static inline bool cmdx_is_v1v2(const cmdx_meta *meta) {
    if (!meta)
        return false;
    return (meta->version == CMDX_V1 || meta->version == CMDX_V2);
}

static inline bool cmdx_is_v1(const cmdx_meta *meta) {
    if (!meta)
        return false;
    return meta->version == CMDX_V1;
}

static inline bool cmdx_is_v2(const cmdx_meta *meta) {
    if (!meta)
        return false;
    return meta->version == CMDX_V2;
}

static inline bool cmdx_is_v3(const cmdx_meta *meta) {
    if (!meta)
        return false;
    return meta->version == CMDX_V3;
}

#ifdef __cplusplus
}
#endif

#endif /* cmdx_meta_h */
