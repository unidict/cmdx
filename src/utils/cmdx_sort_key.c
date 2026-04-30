//
//  cmdx_sort_key.c
//  libcmdx
//
//  Created by kejinlu on 2025/12/19.
//

#include "cmdx_sort_key.h"
#include "cmdx_endian.h"
#include <ctype.h>
#include <string.h>
#include "cmdx_util.h"

static bool is_big5(uint8_t c1, uint8_t c2);
static bool is_gbk(uint8_t c1, uint8_t c2);

static bool mb_get_sort_key(const uint8_t *mb_str, size_t mb_str_len,
                            bool fold_case, bool alpha_and_digit_only,
                            cmdx_encoding encoding, uint8_t **out,
                            size_t *out_len);

static bool wc_get_sort_key(const uint8_t *wc_str, size_t wc_str_len,
                            bool fold_case, bool alpha_and_digit_only,
                            uint8_t **out, size_t *out_len);

// ============================================================================
// Public interface
// ============================================================================
cmdx_data *cmdx_sort_key_data_create(const char *key, cmdx_meta *meta) {
    uint8_t *search_key_bytes = NULL;
    size_t search_key_bytes_len = 0;
    cmdx_utf8_to_encoding(key, meta->encoding,
                             &search_key_bytes, &search_key_bytes_len);
    uint8_t *search_sort_key = NULL;
    size_t search_sort_key_len = 0;
    cmdx_get_sort_key(search_key_bytes, search_key_bytes_len, meta, &search_sort_key,
                 &search_sort_key_len);

    cmdx_data *sort_key_data = calloc(1, sizeof(cmdx_data));
    sort_key_data->data = search_sort_key;
    sort_key_data->length = search_sort_key_len;
    return sort_key_data;
}

// ============================================================================
// Dynamic buffer helper (internal)
// ============================================================================

typedef struct {
    uint8_t *data;
    size_t length;
    size_t capacity;
} ud_dynamic_buffer;

static bool buffer_init(ud_dynamic_buffer *buf, size_t initial_capacity) {
    if (buf == NULL || initial_capacity == 0) {
        return false;
    }

    buf->data = (uint8_t *)malloc(initial_capacity);
    if (buf->data == NULL) {
        return false;
    }

    buf->length = 0;
    buf->capacity = initial_capacity;
    return true;
}

static bool buffer_push(ud_dynamic_buffer *buf, uint8_t byte) {
    if (buf == NULL) {
        return false;
    }

    // Grow if needed
    if (buf->length >= buf->capacity) {
        size_t new_capacity = buf->capacity * 2;
        uint8_t *new_data = (uint8_t *)realloc(buf->data, new_capacity);
        if (new_data == NULL) {
            return false;
        }
        buf->data = new_data;
        buf->capacity = new_capacity;
    }

    buf->data[buf->length++] = byte;
    return true;
}

static bool buffer_append(ud_dynamic_buffer *buf, const uint8_t *data,
                          size_t length) {
    if (buf == NULL || data == NULL) {
        return false;
    }

    // Grow if needed
    if (buf->length + length > buf->capacity) {
        size_t new_capacity = buf->capacity;
        while (new_capacity < buf->length + length) {
            new_capacity *= 2;
        }
        uint8_t *new_data = (uint8_t *)realloc(buf->data, new_capacity);
        if (new_data == NULL) {
            return false;
        }
        buf->data = new_data;
        buf->capacity = new_capacity;
    }

    memcpy(buf->data + buf->length, data, length);
    buf->length += length;
    return true;
}

static void buffer_free(ud_dynamic_buffer *buf) {
    if (buf != NULL && buf->data != NULL) {
        free(buf->data);
        buf->data = NULL;
        buf->length = 0;
        buf->capacity = 0;
    }
}

// ============================================================================
// Character encoding detection
// ============================================================================

static bool is_big5(uint8_t c1, uint8_t c2) {
    return (c1 >= 0xa1) && (c1 <= 0xf9) &&
           ((c2 >= 0x40 && c2 <= 0x7e) || (c2 >= 0xa1 && c2 <= 0xfe));
}

static bool is_gbk(uint8_t c1, uint8_t c2) {
    uint16_t ch = (uint16_t)c1 * 256 + (uint16_t)c2;
    return (ch > 0x8140 && ch < 0xfefe) && c2 != 0xff;
}

// ============================================================================
// Sort key generation
// ============================================================================

static bool mb_get_sort_key(const uint8_t *mb_str, size_t mb_str_len,
                            bool fold_case, bool alpha_and_digit_only,
                            cmdx_encoding encoding, uint8_t **out,
                            size_t *out_len) {
    if (mb_str == NULL || encoding == CMDX_ENCODING_UNKNOWN ||
        out == NULL || out_len == NULL) {
        return false;
    }

    // Initialize output
    *out = NULL;
    *out_len = 0;

    ud_dynamic_buffer buf;
    if (!buffer_init(&buf, mb_str_len > 0 ? mb_str_len : 16)) {
        return false;
    }

    bool is_gbk_encoding = (encoding == CMDX_ENCODING_GBK);
    bool is_big5_encoding = (encoding == CMDX_ENCODING_BIG5);

    for (size_t i = 0; i < mb_str_len; i++) {
        uint8_t ch = mb_str[i];

        // Check for multi-byte character
        if (i < mb_str_len - 1) {
            uint8_t nextch = mb_str[i + 1];
            if ((is_big5_encoding && is_big5(ch, nextch)) ||
                (is_gbk_encoding && is_gbk(ch, nextch))) {
                buffer_push(&buf, ch);
                buffer_push(&buf, nextch);
                i+=2; // Skip next byte
                continue;
            }
        }

        // Case folding
        if (fold_case) {
            if (ch >= 'A' && ch <= 'Z') {
                ch = ch - 'A' + 'a';
                buffer_push(&buf, ch);
                continue;
            }
        }

        // Keep only alphanumeric characters
        if (alpha_and_digit_only) {
            if (isalnum(ch) || ch > 127) {
                buffer_push(&buf, ch);
            }
        } else {
            buffer_push(&buf, ch);
        }
    }

    // Transfer ownership to caller
    *out = buf.data;
    *out_len = buf.length;

    return true;
}

// Write uint16 to buffer (native byte order)
static bool write_uint16_native(ud_dynamic_buffer *buf, uint16_t value) {
    if (buf == NULL) {
        return false;
    }

    uint8_t bytes[2];
    memcpy(bytes, &value, 2);
    return buffer_append(buf, bytes, 2);
}

static bool wc_get_sort_key(const uint8_t *wc_str, size_t wc_str_len,
                            bool fold_case, bool alpha_and_digit_only,
                            uint8_t **out, size_t *out_len) {
    if (wc_str == NULL || out == NULL || out_len == NULL) {
        return false;
    }

    // Initialize output
    *out = NULL;
    *out_len = 0;

    // UTF-16LE string length must be even
    if (wc_str_len % 2 != 0) {
        return false;
    }

    ud_dynamic_buffer buf;
    if (!buffer_init(&buf, wc_str_len > 0 ? wc_str_len : 16)) {
        return false;
    }

    // Read UTF-16LE characters one by one
    for (size_t i = 0; i < wc_str_len; i += 2) {
        uint16_t wc = 0;

        // Read UTF-16LE
        memcpy(&wc, wc_str + i, 2);
        wc = BSWAP16(wc);

        if (wc <= 0xff) {
            uint8_t ch = (uint8_t)wc;

            // Case folding
            if (fold_case) {
                if (ch >= 'A' && ch <= 'Z') {
                    ch = ch - 'A' + 'a';
                    write_uint16_native(&buf, (uint16_t)ch);
                    continue;
                }
            }

            // Keep only alphanumeric characters
            if (alpha_and_digit_only) {
                if (isalnum(ch) || ch > 127) {
                    write_uint16_native(&buf, (uint16_t)ch);
                }
            } else {
                write_uint16_native(&buf, (uint16_t)ch);
            }
        } else {
            // Non-ASCII character: keep as-is
            write_uint16_native(&buf, wc);
        }
    }

    // Transfer ownership to caller
    *out = buf.data;
    *out_len = buf.length;

    return true;
}

bool cmdx_get_sort_key(const uint8_t *key, size_t key_len, const cmdx_meta *meta,
                  uint8_t **out, size_t *out_len) {
    if (key == NULL || meta == NULL || out == NULL || out_len == NULL) {
        return false;
    }

    // Initialize output
    *out = NULL;
    *out_len = 0;

    // V3: no sort key processing; comparison uses UTF-8 directly
    if (cmdx_is_v1v2(meta)) {
        bool fold_case = !meta->key_case_sensitive || !meta->is_mdx;
        bool alpha_and_digit_only = meta->strip_key && meta->is_mdx;
        if (meta->encoding == CMDX_ENCODING_UTF16) {
            return wc_get_sort_key(key, key_len, fold_case, alpha_and_digit_only, out, out_len);
        } else {
            return mb_get_sort_key(key, key_len, fold_case, alpha_and_digit_only, meta->encoding, out, out_len);
        }
    }
    return false;
}
