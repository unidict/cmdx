//
//  ud_mdict_content_section.c
//  libud
//
//  Created by kejinlu on 2025/11/17.
//

#include "cmdx_content_section.h"
#include "cmdx_storage_block.h"
#include "cmdx_util.h"
#include "cmdx_unit_info.h"
#include "cmdx_endian.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// ============================================================
// cmdx_content_block type definition
// ============================================================

static void ud_mdict_content_block_release(uobject *obj);

static const uobject_type ud_mdict_content_block_type = {
    .name = "ud_mdict_content_block",
    .size = sizeof(cmdx_content_block),
    .release = ud_mdict_content_block_release,
};

// MARK: - Private function declarations
static int cmdx_content_block_index_compare(
    cmdx_content_block_index *content_block_index, uint64_t content_offset);
static bool
parse_content_block_index_entries(cmdx_content_section *content_sec,
                                   cmdx_meta *meta, const uint8_t *buffer,
                                   size_t buffer_len);

// MARK: - new & free
/*
 * V1/V2 content section layout — sequential binary format.
 *
 *    section_info          4/8×4 bytes  (block_count, record_count, index_size,
 *                                        block_size; V1: uint32, V2: uint64, big-endian)
 *    block_index_data      index_size   (raw, uncompressed)
 *    content_blocks        block_size   (compressed; lazy-loaded on lookup)
 */
cmdx_content_section *
cmdx_content_section_read_v1v2(FILE *fp, cmdx_meta *meta) {
    if (!fp || !meta) {
        return NULL;
    }

    cmdx_content_section *content_sec = NULL;
    uint8_t *info_buf = NULL;
    uint8_t *block_index_buf = NULL;

    content_sec = calloc(1, sizeof(cmdx_content_section));
    if (!content_sec) {
        goto cleanup;
    }

    size_t number_width = cmdx_is_v1(meta) ? 4 : 8;

    /* ═══════════════════════════════════════════════════════════════════
     * section_info
     *
     *   offset  size  field                endian
     *   ──────  ────  ───────              ──────
     *   0       4/8   block_count          big-endian
     *   4/8     4/8   record_count         big-endian
     *   8/16    4/8   block_index_data_len big-endian
     *   12/24   4/8   block_size           big-endian
     *
     *   V1: 16 bytes (4 × uint32), V2: 32 bytes (4 × uint64).
     * ═══════════════════════════════════════════════════════════════════ */

    size_t info_len = number_width * 4;

    info_buf = malloc(info_len);
    if (!info_buf) {
        goto cleanup;
    }

    size_t read_count = fread(info_buf, info_len, 1, fp);
    if (read_count != 1) {
        goto cleanup;
    }

    // Parse fields
    uint64_t block_count, record_count, block_index_data_len, block_size;
    size_t offset = 0;

    if (cmdx_is_v1(meta)) {
        uint32_t tmp;
        read_uint32_be(info_buf + offset, info_len - offset, &tmp);
        block_count = tmp;
        offset += 4;
        read_uint32_be(info_buf + offset, info_len - offset, &tmp);
        record_count = tmp;
        offset += 4;
        read_uint32_be(info_buf + offset, info_len - offset, &tmp);
        block_index_data_len = tmp;
        offset += 4;
        read_uint32_be(info_buf + offset, info_len - offset, &tmp);
        block_size = tmp;
    } else {
        read_uint64_be(info_buf + offset, info_len - offset, &block_count);
        offset += 8;
        read_uint64_be(info_buf + offset, info_len - offset, &record_count);
        offset += 8;
        read_uint64_be(info_buf + offset, info_len - offset,
                       &block_index_data_len);
        offset += 8;
        read_uint64_be(info_buf + offset, info_len - offset, &block_size);
    }

    free(info_buf);
    info_buf = NULL;

    if (block_count == 0 || record_count == 0 || block_index_data_len == 0) {
        goto cleanup;
    }

    content_sec->block_count = block_count;
    content_sec->total_record_count = record_count;

    /* ═══════════════════════════════════════════════════════════════════
     * content block index data
     *
     *   Read the raw index buffer and parse into block_indexes[].
     * ═══════════════════════════════════════════════════════════════════ */

    block_index_buf = malloc(block_index_data_len);
    if (!block_index_buf) {
        goto cleanup;
    }

    read_count = fread(block_index_buf, block_index_data_len, 1, fp);
    if (read_count != 1) {
        goto cleanup;
    }

    // Record start of content data blocks (lazy-loaded later)
    content_sec->block_offset_in_file = ftell(fp);

    if (!parse_content_block_index_entries(content_sec, meta, block_index_buf,
                                            block_index_data_len)) {
        goto cleanup;
    }

    free(block_index_buf);
    block_index_buf = NULL;

    return content_sec;

cleanup:
    if (info_buf)
        free(info_buf);
    if (block_index_buf)
        free(block_index_buf);
    if (content_sec) {
        if (content_sec->block_indexes) {
            free(content_sec->block_indexes);
        }
        free(content_sec);
    }
    return NULL;
}

/*
 * V3 content section layout — unit-based format.
 *
 *   CONTENT unit           cmdx_unit_info  (unit_type=CONTENT)
 *     ├─ data              (compressed content blocks; skipped during parse)
 *     └─ data_info XML     → encoding, recordCount
 *
 *   CONTENT_BLOCK_INDEX unit  cmdx_unit_info  (unit_type=CONTENT_BLOCK_INDEX)
 *     ├─ data              (actual index; read by seeking back)
 *     └─ data_info XML     → recordCount
 */
cmdx_content_section *cmdx_content_section_read_v3(FILE *fp,
                                                          cmdx_meta *meta) {
    if (!fp || !meta) {
        return NULL;
    }

    cmdx_unit_info content_unit_info = cmdx_unit_info_read(fp);
    if (!content_unit_info.valid ||
        content_unit_info.unit_type != CMDX_V3_UNIT_TYPE_CONTENT) {
        return NULL;
    }

    cmdx_content_section *content_sec = NULL;
    cmdx_data *content_unit_data_info = NULL;
    cmdx_data *content_block_index_unit_data_info = NULL;
    cmdx_data *content_block_index_unit_data = NULL;
    long cur_pos = -1;
    long end_pos = -1;

    content_sec = calloc(1, sizeof(cmdx_content_section));
    if (!content_sec) {
        goto cleanup;
    }

    long content_unit_offset = ftell(fp);
    if (content_unit_offset == -1) {
        goto cleanup;
    }
    content_sec->block_offset_in_file = content_unit_offset;

    /* ═══════════════════════════════════════════════════════════════════
     * CONTENT unit data_info
     *
     *   Read the data_info XML from the CONTENT unit to extract
     *   encoding and recordCount.
     * ═══════════════════════════════════════════════════════════════════ */

    // Skip the unit's data, then read data_info XML
    if (fseek(fp, content_unit_info.data_section_length, SEEK_CUR) != 0) {
        goto cleanup;
    }

    content_unit_data_info = cmdx_storage_block_read_v3(fp, meta);
    if (!content_unit_data_info) {
        goto cleanup;
    }

    char encoding[50] = {0};
    uint64_t record_count = 0;
    cmdx_xml_get_attr((char *)content_unit_data_info->data, "encoding", encoding,
                    sizeof(encoding));
    cmdx_xml_get_attr_uint64((char *)content_unit_data_info->data, "recordCount",
                           &record_count);

    cmdx_data_free_deep(content_unit_data_info);
    content_unit_data_info = NULL;

    /* ═══════════════════════════════════════════════════════════════════
     * CONTENT_BLOCK_INDEX unit data_info
     *
     *   Read the CONTENT_BLOCK_INDEX unit header, skip its data,
     *   then read its data_info XML to extract recordCount.
     *   Save cur_pos / end_pos for seeking back to read the actual index.
     * ═══════════════════════════════════════════════════════════════════ */

    cmdx_unit_info content_block_index_unit_info = cmdx_unit_info_read(fp);
    if (!content_block_index_unit_info.valid ||
        content_block_index_unit_info.unit_type !=
            CMDX_V3_UNIT_TYPE_CONTENT_BLOCK_INDEX) {
        goto cleanup;
    }

    cur_pos = ftell(fp);
    if (cur_pos == -1) {
        goto cleanup;
    }

    // Skip the unit's data, then read data_info XML
    if (fseek(fp, content_block_index_unit_info.data_section_length, SEEK_CUR) != 0) {
        goto cleanup;
    }

    content_block_index_unit_data_info = cmdx_storage_block_read_v3(fp, meta);
    if (!content_block_index_unit_data_info) {
        goto cleanup;
    }

    end_pos = ftell(fp);
    if (end_pos == -1) {
        goto cleanup;
    }

    char index_encoding[50] = {0};
    uint64_t index_record_count = 0;
    cmdx_xml_get_attr((char *)content_block_index_unit_data_info->data, "encoding",
                    index_encoding, sizeof(index_encoding));
    cmdx_xml_get_attr_uint64((char *)content_block_index_unit_data_info->data, "recordCount",
                           &index_record_count);

    content_sec->block_count = content_unit_info.block_count;
    content_sec->total_record_count = index_record_count;

    cmdx_data_free_deep(content_block_index_unit_data_info);
    content_block_index_unit_data_info = NULL;

    if (content_sec->block_count == 0 || content_sec->total_record_count == 0) {
        goto cleanup;
    }

    /* ═══════════════════════════════════════════════════════════════════
     * read and parse the index unit's actual data
     *
     *   Seek back to cur_pos and read the CONTENT_BLOCK_INDEX unit's
     *   full decoded data.  This contains the block index entries
     *   describing each content block (comp/decomp size, offsets).
     * ═══════════════════════════════════════════════════════════════════ */

    if (fseek(fp, cur_pos, SEEK_SET) != 0) {
        goto cleanup;
    }

    content_block_index_unit_data = cmdx_storage_block_read_v3(fp, meta);
    if (!content_block_index_unit_data) {
        goto cleanup;
    }

    if (!parse_content_block_index_entries(content_sec, meta,
                                            content_block_index_unit_data->data,
                                            content_block_index_unit_data->length)) {
        goto cleanup;
    }

    cmdx_data_free_deep(content_block_index_unit_data);
    content_block_index_unit_data = NULL;

    // Restore file position for subsequent reads
    if (fseek(fp, end_pos, SEEK_SET) != 0) {
        goto cleanup;
    }

    return content_sec;

cleanup:
    if (content_unit_data_info) {
        cmdx_data_free_deep(content_unit_data_info);
    }
    if (content_block_index_unit_data_info) {
        cmdx_data_free_deep(content_block_index_unit_data_info);
    }
    if (content_block_index_unit_data) {
        cmdx_data_free_deep(content_block_index_unit_data);
    }
    if (content_sec) {
        if (content_sec->block_indexes) {
            free(content_sec->block_indexes);
        }
        free(content_sec);
    }
    return NULL;
}

void ud_mdict_content_section_free(cmdx_content_section *content_sec) {
    if (!content_sec) {
        return;
    }
    if (content_sec->block_indexes) {
        free(content_sec->block_indexes);
        content_sec->block_indexes = NULL;
    }
    free(content_sec);
}

// MARK: - Block index binary search
cmdx_content_block_index *
ud_mdict_content_block_index_bsearch(cmdx_content_section *content_sec,
                                     uint64_t content_offset) {
    if (!content_sec || !content_sec->block_indexes ||
        content_sec->block_count == 0) {
        return NULL;
    }

    // Binary search
    size_t left = 0;
    size_t right = content_sec->block_count - 1;

    while (left <= right) {
        size_t mid = left + (right - left) / 2;
        cmdx_content_block_index *current =
            &content_sec->block_indexes[mid];

        int cmp = cmdx_content_block_index_compare(current, content_offset);

        if (cmp == 0) {
            // Found the block containing content_offset
            return current;
        } else if (cmp < 0) {
            // content_offset is before the current block range; search left
            if (mid == 0) {
                // Already at the first block, and content_offset is still below its range
                return NULL;
            }
            right = mid - 1;
        } else {
            // content_offset is after the current block range; search right
            left = mid + 1;
        }
    }

    // No block found containing content_offset
    return NULL;
}

// MARK: - Block & record creation with ref counting

cmdx_content_block *cmdx_content_block_read(
    FILE *fp, cmdx_meta *meta,
    cmdx_content_block_index *content_block_index) {
    uint64_t offset_in_file = content_block_index->offset_in_file;
    if (fseek(fp, (long)offset_in_file, SEEK_SET) != 0) {
        return NULL;
    }

    cmdx_data *block_data = NULL;
    if (cmdx_is_v1v2(meta)) {
        block_data =
            cmdx_storage_block_read_v1v2(fp, meta, content_block_index->comp_size,
                                content_block_index->decomp_size);
    } else {
        block_data = cmdx_storage_block_read_v3(fp, meta);
    }

    if (!block_data) {
        return NULL;
    }

    cmdx_content_block *block = calloc(1, sizeof(cmdx_content_block));
    if (!block) {
        cmdx_data_free_deep(block_data);
        return NULL;
    }

    block->data = block_data->data;
    block->length = content_block_index->decomp_size;

    char name_buf[64];
    snprintf(name_buf, sizeof(name_buf), "content_block_%llu",
             content_block_index->logical_offset);
    uobject_init(&block->obj, &ud_mdict_content_block_type, name_buf);

    // Internal data ownership transferred to returned block
    cmdx_data_free_shallow(block_data);

    return block;
}

cmdx_data *cmdx_content_record_extract(
    cmdx_key_entry *key_entry,
    cmdx_content_block_index *content_block_index, cmdx_content_block *content_block) {
    if (!key_entry || !content_block_index || !content_block) {
        return NULL;
    }

    uint64_t content_logical_offset = key_entry->content_logical_offset;

    uint8_t *block_data = content_block->data;
    if (!block_data) {
        return NULL;
    }

    uint64_t offset_in_current_block =
        content_logical_offset - content_block_index->logical_offset;
    uint64_t content_length =
        key_entry->next
            ? (key_entry->next->content_logical_offset - content_logical_offset)
            : (content_block_index->end_logical_offset -
               content_logical_offset);

    if (offset_in_current_block + content_length >
        content_block_index->decomp_size) {
        return NULL;
    }

    size_t copy_len = (size_t)content_length;
    uint8_t *content = (uint8_t *)malloc(copy_len);
    if (!content) {
        return NULL;
    }

    memcpy(content, block_data + offset_in_current_block, copy_len);

    cmdx_data *record = calloc(1, sizeof(cmdx_data));
    if (!record) {
        free(content);
        return NULL;
    }
    record->data = content;
    record->length = copy_len;
    return record;
}

// MARK: - Private functions

static int cmdx_content_block_index_compare(
    cmdx_content_block_index *content_block_index,
    uint64_t content_offset) {
    if (!content_block_index) {
        return -1; // Invalid parameter
    }

    if (content_offset < content_block_index->logical_offset) {
        return -1; // Offset is before block range
    } else if (content_offset >= content_block_index->end_logical_offset) {
        return 1; // Offset is after block range
    } else {
        return 0; // Offset is within block range
    }
}

static void ud_mdict_content_block_release(uobject *obj) {
    cmdx_content_block *block = uobject_cast(obj, cmdx_content_block, obj);
    if (!block) {
        return;
    }

    if (block->data) {
        free(block->data);
    }

    free(block);
}

static bool
parse_content_block_index_entries(cmdx_content_section *content_sec,
                                   cmdx_meta *meta, const uint8_t *buffer,
                                   size_t buffer_len) {
    if (!content_sec || !meta || !buffer) {
        return false;
    }
    if (content_sec->block_count == 0) {
        return false;
    }

    size_t number_width = cmdx_is_v1(meta) ? 4 : 8;
    if (number_width != 4 && number_width != 8) {
        return false;
    }

    cmdx_content_block_index *block_indices =
        calloc(content_sec->block_count, sizeof(cmdx_content_block_index));
    if (!block_indices) {
        return false;
    }

    size_t offset = 0;
    uint64_t comp_offset = content_sec->block_offset_in_file;
    uint64_t logical_offset = 0;

    for (uint64_t i = 0; i < content_sec->block_count; i++) {
        if (offset + number_width * 2 > buffer_len) {
            free(block_indices);
            return false;
        }

        uint64_t comp_size = 0;
        uint64_t decomp_size = 0;

        if (number_width == 4) {
            uint32_t tmp = 0;
            if (!read_uint32_be(buffer + offset, buffer_len - offset, &tmp)) {
                free(block_indices);
                return false;
            }
            comp_size = tmp;
            offset += 4;

            if (!read_uint32_be(buffer + offset, buffer_len - offset, &tmp)) {
                free(block_indices);
                return false;
            }
            decomp_size = tmp;
            offset += 4;
        } else {
            if (!read_uint64_be(buffer + offset, buffer_len - offset,
                                &comp_size)) {
                free(block_indices);
                return false;
            }
            offset += 8;

            if (!read_uint64_be(buffer + offset, buffer_len - offset,
                                &decomp_size)) {
                free(block_indices);
                return false;
            }
            offset += 8;
        }

        block_indices[i].comp_size = comp_size;
        block_indices[i].decomp_size = decomp_size;
        block_indices[i].offset_in_file = comp_offset;
        block_indices[i].logical_offset = logical_offset;
        block_indices[i].end_logical_offset = logical_offset + decomp_size;

        comp_offset += comp_size;
        logical_offset += decomp_size;
    }

    free(content_sec->block_indexes);
    content_sec->block_indexes = block_indices;
    return true;
}
