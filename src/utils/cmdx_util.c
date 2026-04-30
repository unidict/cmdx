//
//  cmdx_util.c
//  libcmdx
//
//  Created by kejinlu on 2025/11/26.
//

#include "cmdx_util.h"
#include "cmdx_meta.h"
#include <iconv.h>
#include <stdlib.h>
#include <string.h>

// ============================================================
// Encoding Conversion (internal helpers)
// ============================================================

// ============================================================
// Encoding Conversion
// ============================================================

int cmdx_encoding_to_utf8(const uint8_t *str_bytes, size_t str_bytes_len,
                          cmdx_encoding encoding, char **output) {
    if (str_bytes_len == 0) {
        *output = "";
        return 0;
    }

    if (str_bytes == NULL || output == NULL) {
        return -1;
    }

    *output = NULL;

    if (str_bytes_len > SIZE_MAX / 2) {
        fprintf(stderr, "Error: input string too long\n");
        return -1;
    }

    if (encoding == CMDX_ENCODING_UTF8) {
        *output = (char *)malloc(str_bytes_len + 1);
        if (*output == NULL) {
            fprintf(stderr, "Error: failed to allocate UTF-8 buffer\n");
            return -1;
        }
        memcpy(*output, str_bytes, str_bytes_len);
        (*output)[str_bytes_len] = '\0';
        return 0;
    }

    const char *from_encoding = cmdx_encoding_name(encoding);
    if (from_encoding == NULL) {
        fprintf(stderr, "Error: unsupported encoding\n");
        return -1;
    }

    iconv_t cd = iconv_open("UTF-8", from_encoding);
    if (cd == (iconv_t)-1) {
        fprintf(stderr, "Error: iconv_open failed\n");
        return -1;
    }

    size_t inbytesleft = str_bytes_len;
    size_t outbytesleft = str_bytes_len * 2;
    *output = (char *)malloc(outbytesleft + 1);
    if (*output == NULL) {
        fprintf(stderr, "Error: failed to allocate UTF-8 buffer\n");
        iconv_close(cd);
        return -1;
    }

    char *inbuf = (char *)str_bytes;
    char *outptr = *output;
    size_t ret = iconv(cd, &inbuf, &inbytesleft, &outptr, &outbytesleft);
    if (ret == (size_t)-1) {
        fprintf(stderr, "Error: iconv conversion failed\n");
        iconv_close(cd);
        free(*output);
        *output = NULL;
        return -1;
    }
    *outptr = '\0';

    iconv_close(cd);

    size_t actual_len = (size_t)(outptr - *output);
    if (actual_len + 1 < str_bytes_len * 2 + 1) {
        char *trimmed = (char *)realloc(*output, actual_len + 1);
        if (trimmed != NULL) {
            *output = trimmed;
        }
    }

    return 0;
}

int cmdx_utf8_to_encoding(const char *str, cmdx_encoding encoding,
                          uint8_t **output, size_t *output_len) {
    if (str == NULL || output == NULL || output_len == NULL) {
        return -1;
    }
    *output = NULL;
    *output_len = 0;

    size_t str_bytes_len = strlen(str);

    if (str_bytes_len == 0) {
        *output = (uint8_t *)"";
        return 0;
    }

    if (str_bytes_len > SIZE_MAX / 2) {
        fprintf(stderr, "Error: input string too long\n");
        return -1;
    }

    if (encoding == CMDX_ENCODING_UTF8) {
        *output = (uint8_t *)malloc(str_bytes_len);
        if (*output == NULL) {
            fprintf(stderr, "Error: failed to allocate output buffer\n");
            return -1;
        }
        memcpy(*output, str, str_bytes_len);
        *output_len = str_bytes_len;
        return 0;
    }

    const char *to_encoding = cmdx_encoding_name(encoding);
    if (to_encoding == NULL) {
        fprintf(stderr, "Error: unsupported encoding\n");
        return -1;
    }

    iconv_t cd = iconv_open(to_encoding, "UTF-8");
    if (cd == (iconv_t)-1) {
        fprintf(stderr, "Error: iconv_open failed\n");
        return -1;
    }

    size_t inbytesleft = str_bytes_len;
    size_t outbytesleft = str_bytes_len * 2;
    *output = (uint8_t *)malloc(outbytesleft);
    if (*output == NULL) {
        fprintf(stderr, "Error: failed to allocate output buffer\n");
        iconv_close(cd);
        return -1;
    }

    char *inbuf = (char *)str;
    char *outptr = (char *)*output;
    size_t ret = iconv(cd, &inbuf, &inbytesleft, &outptr, &outbytesleft);
    if (ret == (size_t)-1) {
        fprintf(stderr, "Error: iconv conversion failed\n");
        iconv_close(cd);
        free(*output);
        *output = NULL;
        return -1;
    }

    iconv_close(cd);

    size_t actual_len = (size_t)(outptr - (char *)*output);
    *output_len = actual_len;

    if (actual_len < str_bytes_len * 2) {
        char *trimmed = (char *)realloc(*output, actual_len);
        if (trimmed != NULL) {
            *output = (uint8_t *)trimmed;
        }
    }

    return 0;
}

// ============================================================
// File I/O
// ============================================================

char *cmdx_path_dup_with_ext(const char *path, const char *new_ext) {
    if (!path || !new_ext) {
        return NULL;
    }

    // Skip leading dots in extension
    while (*new_ext == '.') {
        new_ext++;
    }

    // Find last path separator
#ifdef _WIN32
    const char *last_sep = strrchr(path, '\\');
    const char *last_slash = strrchr(path, '/');
    if (last_slash && (!last_sep || last_slash > last_sep)) {
        last_sep = last_slash;
    }
#else
    const char *last_sep = strrchr(path, '/');
#endif

    // Find last dot in filename
    const char *filename = last_sep ? last_sep + 1 : path;
    const char *last_dot = strrchr(filename, '.');

    size_t prefix_len;
    if (last_dot && last_dot != filename) {
        prefix_len = last_dot - path;
    } else {
        prefix_len = strlen(path);
    }

    size_t len = prefix_len + 1 + strlen(new_ext) + 1;
    char *result = malloc(len);
    if (!result) {
        return NULL;
    }

    memcpy(result, path, prefix_len);
    result[prefix_len] = '.';
    strcpy(result + prefix_len + 1, new_ext);

    return result;
}

char *cmdx_file_read_string(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }

    char *data = NULL;
    if (fseek(fp, 0, SEEK_END) == 0) {
        long length = ftell(fp);
        if (length >= 0 && fseek(fp, 0, SEEK_SET) == 0) {
            size_t size = (size_t)length;
            char *buffer = (char *)malloc(size + 1);
            if (buffer) {
                if (fread(buffer, 1, size, fp) == size) {
                    buffer[size] = '\0';
                    data = buffer;
                } else {
                    free(buffer);
                }
            }
        }
    }

    fclose(fp);
    return data;
}

// ============================================================
// Hex
// ============================================================

static int hex_char_to_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int cmdx_hex_decode(const char *hex_str, uint8_t **out_data) {
    if (!hex_str || !out_data) {
        return -1;
    }

    size_t len = strlen(hex_str);
    if (len % 2 != 0) {
        return -1;
    }

    size_t byte_len = len / 2;
    uint8_t *data = malloc(byte_len);
    if (!data) {
        return -1;
    }

    for (size_t i = 0; i < byte_len; i++) {
        int high = hex_char_to_nibble(hex_str[i * 2]);
        int low  = hex_char_to_nibble(hex_str[i * 2 + 1]);
        if (high == -1 || low == -1) {
            free(data);
            return -1;
        }
        data[i] = (uint8_t)((high << 4) | low);
    }

    *out_data = data;
    return (int)byte_len;
}

// ============================================================
// XML Parsing
// ============================================================

int cmdx_xml_get_attr(const char *xml, const char *attr_name, char *output,
                      size_t out_capacity) {
    if (xml == NULL || attr_name == NULL || output == NULL || out_capacity == 0) {
        return -1;
    }

    char pattern[128];
    snprintf(pattern, sizeof(pattern), "%s=\"", attr_name);

    const char *start = strstr(xml, pattern);
    if (start == NULL) {
        return -1;
    }

    start += strlen(pattern);

    const char *end = strchr(start, '"');
    if (end == NULL) {
        return -1;
    }

    size_t len = end - start;
    if (len >= out_capacity) {
        len = out_capacity - 1;
    }

    memcpy(output, start, len);
    output[len] = '\0';

    return 0;
}

int cmdx_xml_get_attr_uint64(const char *xml, const char *attr_name,
                             uint64_t *output) {
    char buf[32];
    if (cmdx_xml_get_attr(xml, attr_name, buf, sizeof(buf)) != 0) {
        return -1;
    }

    char *endptr;
    uint64_t result = strtoull(buf, &endptr, 10);

    if (endptr == buf || *endptr != '\0') {
        return -1;
    }

    *output = result;
    return 0;
}
