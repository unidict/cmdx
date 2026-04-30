//
//  cmdx_v3_block_info.h
//  libud
//
//  Created by kejinlu on 2025/12/15.
//

#ifndef cmdx_unit_info_h
#define cmdx_unit_info_h

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * V3 unit header — introduced in MDict format version 3.
 *
 * V1/V2 use a fixed sequential layout: the header fields are followed
 * directly by the key section and then the content section, with offsets
 * computed from header metadata alone.  V3 replaces this with a series
 * of typed unit headers that allow flexible, self-describing layout.
 *
 * Each header is a 21-byte record describing a single unit — identified
 * by unit_type as key data, key index, content data, or content index.
 * A logical "section" (e.g. the key section or the content section) is
 * composed of a pair of units: one data unit followed by one index
 * unit.  block_count gives the number of sub-blocks inside the unit's
 * data section, and data_section_length gives the byte size of the
 * unit's data payload.
 */

typedef enum {
    CMDX_V3_UNIT_TYPE_INVALID = 0,
    CMDX_V3_UNIT_TYPE_CONTENT = 1,
    CMDX_V3_UNIT_TYPE_CONTENT_BLOCK_INDEX = 2,
    CMDX_V3_UNIT_TYPE_KEY = 3,
    CMDX_V3_UNIT_TYPE_KEY_BLOCK_INDEX = 4
} cmdx_unit_type;

typedef struct {
    uint8_t unit_type;
    uint8_t reserved1[3];
    uint64_t reserved2;
    uint32_t block_count;
    uint64_t data_section_length;
    bool valid;
} cmdx_unit_info;

cmdx_unit_info cmdx_unit_info_read(FILE *fp);

#ifdef __cplusplus
}
#endif

#endif /* cmdx_unit_info_h */
