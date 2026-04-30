//
//  cmdx_endian.c
//  libcmdx
//
//  Created by kejinlu on 2025/11/24.
//

#include "cmdx_endian.h"
#include <string.h>



/**
 Read from buf
 */
bool read_uint8(const uint8_t *buf, size_t buf_size, uint8_t *out_value) {
    if (buf == NULL || out_value == NULL || buf_size < 1) {
        return false;
    }
    *out_value = buf[0];
    return true;
}

bool read_uint16_be(const uint8_t *buf, size_t buf_size, uint16_t *out_value) {
    if (buf == NULL || out_value == NULL || buf_size < 2) {
        return false;
    }
    uint16_t value;
    memcpy(&value, buf, 2);
    value = BSWAP16(value);
    *out_value = value;
    return true;
}

bool read_uint32_be(const uint8_t *buf, size_t buf_size, uint32_t *out_value) {
    if (buf == NULL || out_value == NULL || buf_size < 4) {
        return false;
    }
    uint32_t value;
    memcpy(&value, buf, 4);
    value = BSWAP32(value);
    *out_value = value;
    return true;
}

bool read_uint32_le(const uint8_t *buf, size_t buf_size, uint32_t *out_value) {
    if (buf == NULL || out_value == NULL || buf_size < 4) {
        return false;
    }
    memcpy(out_value, buf, 4);
    return true;
}

bool read_uint64_be(const uint8_t *buf, size_t buf_size, uint64_t *out_value) {
    if (buf == NULL || out_value == NULL || buf_size < 8) {
        return false;
    }
    uint64_t value;
    memcpy(&value, buf, 8);
    value = BSWAP64(value);
    *out_value = value;
    return true;
}

/**
 Read from file
 */
bool fread_uint8(FILE *fp, uint8_t *out_value) {
    if (fp == NULL || out_value == NULL) {
        return false;
    }
    uint8_t buf[1];
    if (fread(buf, 1, 1, fp) != 1) {
        return false;
    }
    *out_value = buf[0];
    return true;
}

bool fread_uint16_be(FILE *fp, uint16_t *out_value) {
    if (fp == NULL || out_value == NULL) {
        return false;
    }
    uint8_t buf[2];
    if (fread(buf, 1, 2, fp) != 2) {
        return false;
    }
    return read_uint16_be(buf, 2, out_value);
}

bool fread_uint32_le(FILE *fp, uint32_t *out_value) {
    if (fp == NULL || out_value == NULL) {
        return false;
    }
    uint8_t buf[4];
    if (fread(buf, 1, 4, fp) != 4) {
        return false;
    }
    return read_uint32_le(buf, 4, out_value);
}

bool fread_uint32_be(FILE *fp, uint32_t *out_value) {
    if (fp == NULL || out_value == NULL) {
        return false;
    }
    uint8_t buf[4];
    if (fread(buf, 1, 4, fp) != 4) {
        return false;
    }
    return read_uint32_be(buf, 4, out_value);
}

bool fread_uint64_be(FILE *fp, uint64_t *out_value) {
    if (fp == NULL || out_value == NULL) {
        return false;
    }
    uint8_t buf[8];
    if (fread(buf, 1, 8, fp) != 8) {
        return false;
    }
    return read_uint64_be(buf, 8, out_value);
}
