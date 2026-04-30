//
//  cmdx_endian.h
//  libcmdx
//
//  Created by kejinlu on 2025/11/24.
//

#ifndef cmdx_endian_h
#define cmdx_endian_h

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Byte-swap macros
#if defined(__GNUC__) || defined(__clang__)
    #define BSWAP16(x) __builtin_bswap16(x)
    #define BSWAP32(x) __builtin_bswap32(x)
    #define BSWAP64(x) __builtin_bswap64(x)
#elif defined(_MSC_VER)
    #include <stdlib.h>
    #define BSWAP16(x) _byteswap_ushort(x)
    #define BSWAP32(x) _byteswap_ulong(x)
    #define BSWAP64(x) _byteswap_uint64(x)
#else
    #define BSWAP16(x) ((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8))
    #define BSWAP32(x) ((((x) & 0xFF000000) >> 24) | \
                       (((x) & 0x00FF0000) >> 8)  | \
                       (((x) & 0x0000FF00) << 8)  | \
                       (((x) & 0x000000FF) << 24))
    #define BSWAP64(x) ((((x) & 0xFF00000000000000) >> 56) | \
                       (((x) & 0x00FF000000000000) >> 40) | \
                       (((x) & 0x0000FF0000000000) >> 24) | \
                       (((x) & 0x000000FF00000000) >> 8)  | \
                       (((x) & 0x00000000FF000000) << 8)  | \
                       (((x) & 0x0000000000FF0000) << 24) | \
                       (((x) & 0x000000000000FF00) << 40) | \
                       (((x) & 0x00000000000000FF) << 56))
#endif

/**
 Read from buf
 */
bool read_uint8(const uint8_t *buf, size_t buf_size, uint8_t *out_value);
bool read_uint16_be(const uint8_t *buf, size_t buf_size, uint16_t *out_value);
bool read_uint32_le(const uint8_t *buf, size_t buf_size, uint32_t *out_value);
bool read_uint32_be(const uint8_t *buf, size_t buf_size, uint32_t *out_value);
bool read_uint64_be(const uint8_t *buf, size_t buf_size, uint64_t *out_value);

/**
 Read from file
 */
bool fread_uint8(FILE *fp, uint8_t *out_value);
bool fread_uint16_be(FILE *fp, uint16_t *out_value);
bool fread_uint32_le(FILE *fp, uint32_t *out_value);
bool fread_uint32_be(FILE *fp, uint32_t *out_value);
bool fread_uint64_be(FILE *fp, uint64_t *out_value);


#ifdef __cplusplus
}
#endif

#endif /* cmdx_endian_h */
