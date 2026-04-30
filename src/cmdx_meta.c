//
//  ud_mdict_meta.c
//  libud
//
//  Created by kejinlu on 2025/11/17.
//

#include "cmdx_meta.h"
#include <zlib.h>
#include "cmdx_endian.h"
#include <iconv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif

// MARK: - Private declaration
static void mdict_meta_set_string(char **field, const char *value);
static cmdx_encoding parse_encoding(const char *str);
static cmdx_format parse_format(const char *str);
static bool parse_bool(const char *str);
static uint8_t parse_encrypted(const char *str);
static void parse_meta_xml(const char *xml_string, cmdx_meta *meta);

// MARK: - Public function

cmdx_meta *cmdx_meta_read(FILE *file) {
    if (!file) {
        return NULL;
    }

    char *xml_buffer = NULL;
    iconv_t cd = (iconv_t)-1;
    cmdx_meta *meta = NULL;

    /* ═══════════════════════════════════════════════════════════════════
     * Header reading
     *
     *   offset  size  field        endian
     *   ──────  ────  ───────      ──────
     *   0       4     data_size    big-endian
     *   4       N     data         (raw bytes, may be UTF-16LE encoded XML)
     *   4+N     4     adler32      little-endian  (checksum of data)
     * ═══════════════════════════════════════════════════════════════════ */

    // Read data_size
    uint32_t data_size;
    if (!fread_uint32_be(file, &data_size)) {
        return NULL;
    }
    if (data_size == 0 || data_size > 10 * 1024 * 1024) {
        fprintf(stderr, "Error: invalid MDict header size: %u\n", data_size);
        return NULL;
    }

    // Read header_data
    xml_buffer = malloc(data_size);
    if (!xml_buffer) {
        fprintf(stderr, "Error: failed to allocate memory for MDict header\n");
        return NULL;
    }
    size_t bytes_read = fread(xml_buffer, 1, data_size, file);
    if (bytes_read != data_size) {
        fprintf(stderr,
                "Error: failed to read MDict header (expected %u bytes, got %zu)\n",
                data_size, bytes_read);
        goto cleanup;
    }

    // Read adler32 checksum
    uint32_t checksum;
    if (!fread_uint32_le(file, &checksum)) {
        fprintf(stderr, "Error: failed to read checksum\n");
        goto cleanup;
    }

    // Verify checksum
    uLong xml_checksum =
        adler32(1L, (const unsigned char *)xml_buffer, (uInt)data_size);
    if (xml_checksum != checksum) {
        fprintf(stderr, "Error: checksum verification failed\n");
        goto cleanup;
    }

    /* ═══════════════════════════════════════════════════════════════════
     * Encoding conversion (UTF-16LE → UTF-8)
     * ═══════════════════════════════════════════════════════════════════ */

    if (xml_buffer[0] == '<' && xml_buffer[1] == '\0') {
        // In UTF-16LE, the ASCII character '<' is encoded as two bytes: 0x3C 0x00.
        // So if the first byte is '<' (0x3C) and the second is 0x00, it's UTF-16LE.
        char *outbuf = NULL;

        cd = iconv_open("UTF-8", "UTF-16LE");
        if (cd == (iconv_t)-1) {
            fprintf(stderr, "Error: failed to initialize encoding converter\n");
            goto cleanup;
        }

        // Allocate output buffer (UTF-8 is at most 1.5x UTF-16; use 2x conservatively)
        size_t inbytesleft = data_size;
        size_t outbytesleft = inbytesleft * 2;
        outbuf = malloc(outbytesleft + 1);
        if (!outbuf) {
            fprintf(stderr, "Error: failed to allocate memory for encoding conversion\n");
            goto cleanup;
        }

        // Perform encoding conversion
        char *inptr = xml_buffer;
        char *outptr = outbuf;
        size_t result = iconv(cd, &inptr, &inbytesleft, &outptr, &outbytesleft);
        if (result == (size_t)-1) {
            fprintf(stderr, "Warning: encoding conversion may be incomplete\n");
            // Continue parsing; partial conversion may still be usable
        }
        *outptr = '\0';
        iconv_close(cd);
        free(xml_buffer);

        xml_buffer = outbuf;
    }

    /* ═══════════════════════════════════════════════════════════════════
     * XML parsing
     * ═══════════════════════════════════════════════════════════════════ */

    // Allocate meta struct
    meta = calloc(1, sizeof(cmdx_meta));
    if (!meta) {
        fprintf(stderr, "Error: failed to allocate memory for meta struct\n");
        goto cleanup;
    }

    // Parse XML
    parse_meta_xml(xml_buffer, meta);

    if (meta->encoding == CMDX_ENCODING_UNKNOWN) {
        if (cmdx_is_v3(meta)) {
            meta->encoding = CMDX_ENCODING_UTF8;
        } else {
            meta->encoding = CMDX_ENCODING_UTF16;
        }
    }
    // Set derived fields
    meta->is_utf16 = (meta->encoding == CMDX_ENCODING_UTF16);

    // Clean up temporary resources
    free(xml_buffer);

    return meta;

cleanup:
    // Unified resource cleanup
    if (xml_buffer)
        free(xml_buffer);
    if (cd != (iconv_t)-1)
        iconv_close(cd);
    if (meta)
        cmdx_meta_free(meta);
    return NULL;
}

void cmdx_meta_free(cmdx_meta *meta) {
    if (meta == NULL)
        return;

    // Free all dynamically allocated string fields
    free(meta->creation_date);
    free(meta->description);
    free(meta->title);
    free(meta->style_sheet);
    free(meta->register_by);
    free(meta->reg_code);
    free(meta->uuid);
    free(meta);
}

const char* cmdx_encoding_name(cmdx_encoding encoding) {
    switch (encoding) {
        case CMDX_ENCODING_UTF8:
            return "UTF-8";
        case CMDX_ENCODING_UTF16:
            return "UTF-16LE";
        case CMDX_ENCODING_GBK:
            return "GBK";
        case CMDX_ENCODING_GB2312:
            return "GB2312";
        case CMDX_ENCODING_GB18030:
            return "GB18030";
        case CMDX_ENCODING_BIG5:
            return "BIG5";
        case CMDX_ENCODING_UNKNOWN:
        default:
            return NULL;
    }
}

// MARK: - Private function
static void mdict_meta_set_string(char **field, const char *value) {
    if (field == NULL)
        return;
    free(*field);
    *field = value ? strdup(value) : NULL;
}

static cmdx_encoding parse_encoding(const char *str) {

    if (str == NULL || str[0] == '\0') {
        return CMDX_ENCODING_UNKNOWN;
    }

    // UTF-8
    if (strcasecmp(str, "UTF-8") == 0 ||
        strcasecmp(str, "UTF8") == 0) {
        return CMDX_ENCODING_UTF8;
    }

    // GBK and GB2312 unified as GB18030
    if (strcasecmp(str, "GBK") == 0 || strcasecmp(str, "GB2312") == 0) {
        return CMDX_ENCODING_GB18030;
    }

    // Big5
    if (strcasecmp(str, "Big5") == 0 || strcasecmp(str, "BIG5") == 0) {
        return CMDX_ENCODING_BIG5;
    }

    // UTF-16
    if (strcasecmp(str, "UTF-16") == 0 || strcasecmp(str, "UTF16") == 0) {
        return CMDX_ENCODING_UTF16;
    }

    // Default to UTF-8
    return CMDX_ENCODING_UTF8;
}

// Parse format string
static cmdx_format parse_format(const char *str) {
    if (str == NULL)
        return CMDX_FORMAT_NONE;

    if (strcasecmp(str, "Html") == 0) {
        return CMDX_FORMAT_HTML;
    } else if (strcasecmp(str, "Text") == 0) {
        return CMDX_FORMAT_TEXT;
    }
    return CMDX_FORMAT_NONE;
}

// Parse boolean value
static bool parse_bool(const char *str) {
    if (str == NULL)
        return false;

    return (strcasecmp(str, "Yes") == 0 || strcasecmp(str, "True") == 0 ||
            strcmp(str, "1") == 0);
}

static uint8_t parse_encrypted(const char *str) {
    if (str == NULL || str[0] == '\0') {
        return CMDX_KEY_BLOCK_INDEX_ENCRYPTION_TYPE_NONE;
    }
    // Only keep the two recognized bits; discard the rest
    int value = atoi(str);
    return ((uint8_t)value) & CMDX_KEY_BLOCK_INDEX_ENCRYPTION_TYPE_ALL;
}

static void parse_meta_xml(const char *xml_string, cmdx_meta *meta) {
    if (xml_string == NULL || meta == NULL) {
        return;
    }

    size_t length = strlen(xml_string);
    if (length <= 2) {
        return;
    }

    // Trim trailing whitespace
    size_t end_pos = length - 1;
    while (end_pos != (size_t)-1 &&
           (xml_string[end_pos] == ' ' || xml_string[end_pos] == '\n' ||
            xml_string[end_pos] == '\0' || xml_string[end_pos] == '\r' ||
            xml_string[end_pos] == '\t')) {
        --end_pos;
    }

    size_t effective_length = end_pos + 1;
    if (effective_length <= 2) {
        return;
    }

    // Verify XML tag ends with "/>" or ">"
    const char last2 = xml_string[effective_length - 2];
    const char last1 = xml_string[effective_length - 1];
    if (!((last2 == '/' && last1 == '>') || last1 == '>')) {
        return;
    }

    // Skip leading whitespace and '<'
    size_t pos = 0;
    while (pos < effective_length &&
           (xml_string[pos] == ' ' || xml_string[pos] == '\n' ||
            xml_string[pos] == '\r' || xml_string[pos] == '\t' ||
            xml_string[pos] == '<')) {
        ++pos;
    }

    // Skip tag name (e.g. "Dictionary")
    while (pos < effective_length && xml_string[pos] != ' ' &&
           xml_string[pos] != '>' && xml_string[pos] != '/') {
        ++pos;
    }

    // Parse attributes loop
    while (pos < effective_length - 1) {
        // Skip whitespace between attributes
        while (pos < effective_length &&
               (xml_string[pos] == ' ' || xml_string[pos] == '\n' ||
                xml_string[pos] == '\r' || xml_string[pos] == '\t')) {
            ++pos;
        }

        // Check for tag end
        if (pos >= effective_length) {
            break;
        }

        if (xml_string[pos] == '>' ||
            (pos + 1 < effective_length && xml_string[pos] == '/' &&
             xml_string[pos + 1] == '>')) {
            break;
        }

        // Extract attribute name (key)
        char key[256] = {0};
        size_t key_len = 0;
        while (pos < effective_length && xml_string[pos] != '=' &&
               xml_string[pos] != ' ' && xml_string[pos] != '\n' &&
               xml_string[pos] != '\r' && xml_string[pos] != '\t' &&
               xml_string[pos] != '>' && xml_string[pos] != '/' &&
               key_len < 255) {
            key[key_len++] = xml_string[pos++];
        }
        key[key_len] = '\0';

        // Skip if no valid key was extracted
        if (key_len == 0) {
            ++pos;
            continue;
        }

        // Skip whitespace and '='
        while (pos < effective_length &&
               (xml_string[pos] == ' ' || xml_string[pos] == '\n' ||
                xml_string[pos] == '\r' || xml_string[pos] == '\t' ||
                xml_string[pos] == '=')) {
            ++pos;
        }

        // Extract attribute value
        char value[4096] = {0};
        size_t value_len = 0;

        if (pos < effective_length && xml_string[pos] == '"') {
            ++pos; // Skip opening quote

            while (pos < effective_length && value_len < 4095) {
                if (xml_string[pos] == '"') {
                    ++pos; // Skip closing quote
                    break;
                }
                // Handle escape character
                if (xml_string[pos] == '\\' && pos + 1 < effective_length) {
                    ++pos; // Skip backslash
                }
                value[value_len++] = xml_string[pos++];
            }
            value[value_len] = '\0';
        }

        // Set corresponding field based on attribute name
        if (strcasecmp(key, "RequiredEngineVersion") == 0) {
            float version = value[0] != '\0' ? strtof(value, NULL) : 0.0f;
            meta->version = (int)version;
        } else if (strcasecmp(key, "Encrypted") == 0) {
            meta->encrypted = parse_encrypted(value);
        } else if (strcasecmp(key, "Encoding") == 0) {
            meta->encoding = parse_encoding(value);
        } else if (strcasecmp(key, "Format") == 0) {
            meta->format = parse_format(value);
        } else if (strcasecmp(key, "CreationDate") == 0) {
            mdict_meta_set_string(&meta->creation_date, value);
        } else if (strcasecmp(key, "Compact") == 0) {
            meta->compact = parse_bool(value);
        } else if (strcasecmp(key, "Compat") == 0) {
            meta->compat = parse_bool(value);
        } else if (strcasecmp(key, "KeyCaseSensitive") == 0) {
            meta->key_case_sensitive = parse_bool(value);
        } else if (strcasecmp(key, "Description") == 0) {
            mdict_meta_set_string(&meta->description, value);
        } else if (strcasecmp(key, "Title") == 0) {
            mdict_meta_set_string(&meta->title, value);
        } else if (strcasecmp(key, "StyleSheet") == 0) {
            mdict_meta_set_string(&meta->style_sheet, value);
        } else if (strcasecmp(key, "RegisterBy") == 0) {
            mdict_meta_set_string(&meta->register_by, value);
        } else if (strcasecmp(key, "RegCode") == 0) {
            mdict_meta_set_string(&meta->reg_code, value);
        } else if (strcasecmp(key, "StripKey") == 0) {
            meta->strip_key = parse_bool(value);
        } else if (strcasecmp(key, "Left2Right") == 0) {
            meta->left2right = parse_bool(value);
        } else if (strcasecmp(key, "UUID") == 0) {
            mdict_meta_set_string(&meta->uuid, value);
        } else if (strcasecmp(key, "DefaultSortingLocale") == 0) {
            mdict_meta_set_string(&meta->default_sorting_locale, value);
        }
        // Ignore unknown attributes
    }
}
