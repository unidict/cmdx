//
//  cmdx_key_section.h
//  libcmdx
//
//  Created by kejinlu on 2025/11/17.
//

#ifndef cmdx_key_section_h
#define cmdx_key_section_h

#include "cmdx_types.h"
#include "uobject.h"
#include "cmdx_meta.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct UCollator cmdx_icu_collator;
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct cmdx_key_entry cmdx_key_entry;

/*
 * Key block index — summary of a single compressed key block.
 * Used for binary search to locate which block contains a given keyword.
 * Fields are ordered by size for memory alignment.
 */
typedef struct {
    // Pointer fields (8 bytes)
    char *first_key;       // First keyword in this block
    char *last_key;        // Last keyword in this block

    uint8_t *first_sort_key;
    uint8_t *last_sort_key;
    size_t first_sort_key_len;
    size_t last_sort_key_len;

    // uint64_t fields (8 bytes)
    uint64_t comp_size;      // Compressed block size
    uint64_t decomp_size;    // Decompressed block size
    uint64_t entry_count;    // Number of entries in this block
    uint64_t offset_in_file; // File offset of this block
} cmdx_key_block_index;

typedef struct {
    uobject obj;                          // Embedded ref-counted object (must be first member)
    cmdx_key_entry **key_entries;     // Array of key entries
    size_t key_entry_count;
} cmdx_key_block;

struct cmdx_key_entry {
    uobject obj;                  // Embedded ref-counted object
    char *key;                    // Keyword string
    uint8_t *key_raw;             // Raw bytes of the keyword
    uint8_t *sort_key;            // Sort key for comparison
    size_t key_raw_len;
    size_t sort_key_len;
    uint64_t content_logical_offset;  // Logical offset in the content data stream
    uint64_t entry_no;                // Entry number (sequential index)
    cmdx_key_entry *next;             // Next entry in the same block
};

/*
 * Key section — contains all keyword block indexes and key data blocks.
 */
typedef struct {
    cmdx_key_block_index *block_indexes;
    uint64_t block_count;
    uint64_t block_offset_in_file;

    uint64_t key_count;
} cmdx_key_section;

cmdx_key_section *cmdx_key_section_read_v1v2(FILE *fp, cmdx_meta *meta);
cmdx_key_section *cmdx_key_section_read_v3(FILE *fp, cmdx_meta *meta);
void cmdx_key_section_free(cmdx_key_section *key_sec);

cmdx_key_block *
cmdx_key_block_read(FILE *fp, cmdx_meta *meta,
                     cmdx_key_block_index *key_block_index);

cmdx_key_block_index *
cmdx_key_block_index_bsearch_first(cmdx_key_section *key_sec,
                                   cmdx_meta *meta, const char *key,
                                   cmdx_icu_collator *collator, bool prefix);

cmdx_key_entry *
cmdx_key_entry_bsearch_first(cmdx_key_block *key_block,
                             cmdx_meta *meta, const char *key,
                             cmdx_icu_collator *collator, bool prefix);

int cmdx_key_cmp(const char *k1, const uint8_t *sort_k1,
                 const size_t sort_k1_len, const char *k2,
                 const uint8_t *sort_k2, const size_t sort_k2_len,
                 bool prefix, cmdx_meta *meta, cmdx_icu_collator *collator);

#ifdef __cplusplus
}
#endif

#endif /* cmdx_key_section_h */
