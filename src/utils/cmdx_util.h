//
//  cmdx_util.h
//  libcmdx
//
//  Created by kejinlu on 2025/11/26.
//

#ifndef cmdx_util_h
#define cmdx_util_h

#include "cmdx_meta.h"
#include "cmdx_types.h"
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// Encoding Conversion
// ============================================================

int cmdx_encoding_to_utf8(const uint8_t *str_bytes, size_t str_bytes_len,
                           cmdx_encoding encoding, char **output);

int cmdx_utf8_to_encoding(const char *str, cmdx_encoding encoding,
                           uint8_t **output, size_t *output_len);

// ============================================================
// File I/O
// ============================================================

char *cmdx_path_dup_with_ext(const char *path, const char *new_ext);

char *cmdx_file_read_string(const char *path);

// ============================================================
// Hex
// ============================================================

int cmdx_hex_decode(const char *hex_str, uint8_t **out_data);

// ============================================================
// XML Parsing
// ============================================================

int cmdx_xml_get_attr(const char *xml, const char *attr_name, char *output,
                      size_t out_capacity);

int cmdx_xml_get_attr_uint64(const char *xml, const char *attr_name,
                             uint64_t *output);

#ifdef __cplusplus
}
#endif

#endif /* cmdx_util_h */
