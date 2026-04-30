//
//  ud_mdict_content_section.h
//  libud
//
//  Created by kejinlu on 2025/11/17.
//

#ifndef cmdx_content_section_h
#define cmdx_content_section_h

#include "cmdx_types.h"
#include "uobject.h"
#include "cmdx_key_section.h"
#include "cmdx_meta.h"
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t comp_size;
    uint64_t decomp_size;

    uint64_t offset_in_file;

    // Logical offset within the concatenated uncompressed block data
    uint64_t logical_offset;
    uint64_t end_logical_offset;
} cmdx_content_block_index;

typedef struct {
    uobject obj;          // Embedded ref-counted object (must be first member)
    uint8_t *data;
    size_t length;
} cmdx_content_block;

typedef struct {
    cmdx_content_block_index *block_indexes;
    uint64_t block_count;
    uint64_t block_offset_in_file;

    uint64_t total_record_count;
} cmdx_content_section;

cmdx_content_section *
cmdx_content_section_read_v1v2(FILE *fp, cmdx_meta *meta);
cmdx_content_section *cmdx_content_section_read_v3(FILE *fp,
                                                         cmdx_meta *meta);
void ud_mdict_content_section_free(cmdx_content_section *content_sec);

cmdx_content_block_index *
ud_mdict_content_block_index_bsearch(cmdx_content_section *content_sec,
                                     uint64_t content_offset);

cmdx_content_block *cmdx_content_block_read(
    FILE *fp, cmdx_meta *meta,
    cmdx_content_block_index *content_block_index);

cmdx_data *cmdx_content_record_extract(
    cmdx_key_entry *key_entry,
    cmdx_content_block_index *content_block_index, cmdx_content_block *content_block);
#ifdef __cplusplus
}
#endif

#endif /* cmdx_content_section_h */
