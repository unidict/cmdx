//
//  cmdx_key_section.c
//  libcmdx
//
//  Created by kejinlu on 2025/11/17.
//

#include "cmdx_key_section.h"
#include "cmdx_icu.h"
#include <zlib.h>
#include "stdlib.h"
#include "cmdx_crypto.h"
#include "cmdx_sort_key.h"
#include "cmdx_storage_block.h"
#include "cmdx_util.h"
#include "cmdx_unit_info.h"
#include "cmdx_endian.h"
#include <string.h>

// ============================================================
// Object type definitions
// ============================================================

static void ud_mdict_key_entry_release(uobject *obj);
static void ud_mdict_key_block_release(uobject *obj);

static const uobject_type ud_mdict_key_entry_type = {
    .name = "cmdx_key_entry",
    .size = sizeof(struct cmdx_key_entry),
    .release = ud_mdict_key_entry_release,
};

static const uobject_type ud_mdict_key_block_type = {
    .name = "cmdx_key_block",
    .size = sizeof(cmdx_key_block),
    .release = ud_mdict_key_block_release,
};

// ============================================================
// Forward declarations (static)
// ============================================================

static int parse_key_block_index_entries(cmdx_key_section *key_sec,
                                         cmdx_meta *meta,
                                         uint8_t *index_buf,
                                         uint64_t index_len);
static int key_block_index_init(cmdx_key_block_index *index, uint8_t *buf,
                                size_t buf_len, size_t *offset,
                                cmdx_meta *meta);
static int key_block_index_read_key(uint8_t *buf, size_t buf_len,
                                    size_t *offset, cmdx_meta *meta,
                                    uint8_t **out_key_raw,
                                    size_t *out_key_raw_len);
static int cmdx_key_block_index_cmp(const char *key,
                                        const cmdx_data *sort_key_data,
                                        const cmdx_key_block_index *index,
                                        cmdx_meta *meta, cmdx_icu_collator *collator, bool prefix);
static cmdx_key_block_index *cmdx_key_block_index_bsearch_first_by_sort_key(
    cmdx_key_section *key_sec, cmdx_meta *meta, const char *key,
    const cmdx_data *sort_key_data, cmdx_icu_collator *collator, bool prefix);
static cmdx_key_entry *cmdx_key_entry_bsearch_first_by_sort_key(
    cmdx_key_block *key_block, cmdx_meta *meta, const char *key,
    const cmdx_data *sort_key_data, cmdx_icu_collator *collator, bool prefix);
static int sort_key_cmp(const uint8_t *bytes1, size_t len1,
                        const uint8_t *bytes2, size_t len2, bool prefix);

// ============================================================
// Public: section parse & free
// ============================================================

/*
 * V1/V2 key section layout — sequential binary format.
 *
 *    section_info         16/40 bytes  (V1: 4×uint32, V2: 5×uint64, big-endian;
 *                                       V2 paragraph may be Salsa20-encrypted)
 *    checksum             4 bytes      (V2 only; ADLER32 of section_info)
 *    key_block_index_data index_len    (V2: zlib-compressed, optionally encrypted)
 *    key_blocks           blocks_len   (compressed; lazy-loaded on lookup)
 */
cmdx_key_section *cmdx_key_section_read_v1v2(FILE *fp, cmdx_meta *meta) {
    if (!fp || !meta) {
        return NULL;
    }

    cmdx_key_section *key_sec = NULL;
    uint8_t *info_buf = NULL;
    uint8_t *key_block_index_buf = NULL;
    uint8_t *out_buf = NULL;
    uint8_t *block_index_data_crypto_key_buf = NULL;
    uint8_t block_index_data_crypto_key[CMDX_HASH128_SIZE];

    key_sec = calloc(1, sizeof(cmdx_key_section));
    if (!key_sec) {
        return NULL;
    }

    bool is_v2 = cmdx_is_v2(meta);

    /* ═══════════════════════════════════════════════════════════════════
     * section_info
     *
     *   offset  size  field             endian
     *   ──────  ────  ───────           ──────
     *   0       4/8   num_blocks        big-endian
     *   4/8     4/8   num_entries       big-endian
     *   8/16    4/8   index_decomp_len  big-endian  (V2 only)
     *   12/24   4/8   index_len         big-endian
     *   16/32   4/8   blocks_len        big-endian
     *
     *   V1: 16 bytes (4 × uint32), V2: 40 bytes (5 × uint64).
     *   In V2, the whole section_info may be Salsa20-encrypted.
     * ═══════════════════════════════════════════════════════════════════ */

    size_t info_buf_len = is_v2 ? 40 : 16;

    info_buf = (uint8_t *)malloc(info_buf_len);
    if (!info_buf) {
        goto cleanup;
    }

    // Read raw section_info
    if (fread(info_buf, info_buf_len, 1, fp) != 1) {
        goto cleanup;
    }

    // Decrypt if paragraph encryption is enabled (V2 only)
    if (is_key_block_index_info_encrypted(meta)) {
        uint8_t *decrypted_info_buf =
            cmdx_salsa20_decrypt(info_buf, info_buf_len, meta->crypto_key, 128);
        free(info_buf);
        info_buf = decrypted_info_buf;
        if (!info_buf) {
            goto cleanup;
        }
    }

    // Parse fields
    uint64_t num_blocks, num_entries, index_decomp_len = 0, index_len, blocks_len;

    size_t offset = 0;
    if (is_v2) {
        read_uint64_be(info_buf + offset, info_buf_len - offset, &num_blocks);
        offset += 8;
        read_uint64_be(info_buf + offset, info_buf_len - offset, &num_entries);
        offset += 8;
        read_uint64_be(info_buf + offset, info_buf_len - offset, &index_decomp_len);
        offset += 8;
        read_uint64_be(info_buf + offset, info_buf_len - offset, &index_len);
        offset += 8;
        read_uint64_be(info_buf + offset, info_buf_len - offset, &blocks_len);
    } else {
        uint32_t temp_val;
        read_uint32_be(info_buf + offset, info_buf_len - offset, &temp_val);
        num_blocks = temp_val;
        offset += 4;
        read_uint32_be(info_buf + offset, info_buf_len - offset, &temp_val);
        num_entries = temp_val;
        offset += 4;
        read_uint32_be(info_buf + offset, info_buf_len - offset, &temp_val);
        index_len = temp_val;
        offset += 4;
        read_uint32_be(info_buf + offset, info_buf_len - offset, &temp_val);
        blocks_len = temp_val;
    }

    if (num_blocks == 0 || num_entries == 0 || index_len == 0) {
        goto cleanup;
    }

    key_sec->block_count = num_blocks;
    key_sec->key_count = num_entries;

    /* ═══════════════════════════════════════════════════════════════════
     * checksum (V2 only)
     *
     *   ADLER32 of the section_info bytes (before decryption).
     * ═══════════════════════════════════════════════════════════════════ */

    if (is_v2) {
        uint32_t checksum = 0;
        if (!fread_uint32_be(fp, &checksum)) {
            goto cleanup;
        }
        uLong header_checksum = adler32(1L, info_buf, (uInt)info_buf_len);
        if (header_checksum != checksum) {
            goto cleanup;
        }
    }

    free(info_buf);
    info_buf = NULL;

    /* ═══════════════════════════════════════════════════════════════════
     * key block index data
     *
     *   Read the compressed (and possibly encrypted) index buffer.
     *   For V2: decrypt → decompress before parsing.
     * ═══════════════════════════════════════════════════════════════════ */

    // Read raw index data
    key_block_index_buf = (uint8_t *)malloc((size_t)index_len);
    if (!key_block_index_buf) {
        goto cleanup;
    }
    if (fread(key_block_index_buf, (size_t)index_len, 1, fp) != 1) {
        goto cleanup;
    }

    // Record the start of key data blocks (lazy-loaded later)
    key_sec->block_offset_in_file = ftell(fp);

    // V2: decrypt and decompress
    if (is_v2) {
        if (index_len < 8) {
            goto cleanup;
        }

        // Verify compression type is zlib (0x02 0x00 0x00 0x00)
        if (!(key_block_index_buf[0] == 0x02 &&
              key_block_index_buf[1] == 0x00 &&
              key_block_index_buf[2] == 0x00 &&
              key_block_index_buf[3] == 0x00)) {
            goto cleanup;
        }

        uint32_t keyword_index_checksum_be = 0;
        memcpy(&keyword_index_checksum_be, key_block_index_buf + 4, 4);
        uint32_t keyword_index_checksum = BSWAP32(keyword_index_checksum_be);
        (void)keyword_index_checksum;

        // Decrypt if data encryption is enabled
        if (is_key_block_index_data_encrypted(meta)) {
            block_index_data_crypto_key_buf = (uint8_t *)calloc(8, sizeof(uint8_t));
            if (!block_index_data_crypto_key_buf) {
                goto cleanup;
            }

            memcpy(block_index_data_crypto_key_buf, key_block_index_buf + 4, 4);
            block_index_data_crypto_key_buf[4] = 0x95;
            block_index_data_crypto_key_buf[5] = 0x36;

            if (cmdx_ripemd128_hash(block_index_data_crypto_key_buf, 8,
                               block_index_data_crypto_key) != 0) {
                goto cleanup;
            }

            cmdx_simple_decrypt_inplace(key_block_index_buf + 8,
                                   (int)(index_len - 8),
                                   block_index_data_crypto_key, 16);
            free(block_index_data_crypto_key_buf);
            block_index_data_crypto_key_buf = NULL;
        }

        // Decompress
        if (index_decomp_len == 0) {
            goto cleanup;
        }

        size_t out_cap = (size_t)index_decomp_len;
        out_buf = (uint8_t *)malloc(out_cap);
        if (!out_buf) {
            goto cleanup;
        }

        int rc = cmdx_storage_block_decode(key_block_index_buf, (size_t)index_len, NULL, 0,
                              out_buf, &out_cap);
        if (rc != 0) {
            goto cleanup;
        }

        free(key_block_index_buf);
        key_block_index_buf = out_buf;
        out_buf = NULL;
        index_len = out_cap;
    }

    /* ═══════════════════════════════════════════════════════════════════
     * parse index entries, skip data blocks
     *
     *   Parse the decompressed index buffer into block_indexes[].
     *   Key data blocks are skipped — they are lazy-loaded on lookup.
     * ═══════════════════════════════════════════════════════════════════ */

    if (parse_key_block_index_entries(key_sec, meta, key_block_index_buf, index_len) != 0) {
        goto cleanup;
    }

    free(key_block_index_buf);
    key_block_index_buf = NULL;

    // Skip over key data blocks (lazy-loaded on lookup)
    if (fseek(fp, blocks_len, SEEK_CUR) != 0) {
        // Non-fatal: block indexes are already parsed
    }

    return key_sec;

cleanup:
    free(info_buf);
    free(key_block_index_buf);
    free(out_buf);
    free(block_index_data_crypto_key_buf);
    cmdx_key_section_free(key_sec);
    return NULL;
}

/*
 * V3 key section layout — unit-based format.
 *
 *   KEY unit              cmdx_unit_info  (unit_type=KEY)
 *     ├─ data             (compressed key blocks; skipped during parse)
 *     └─ data_info XML    → keyCount
 *
 *   KEY_BLOCK_INDEX unit  cmdx_unit_info  (unit_type=KEY_BLOCK_INDEX)
 *     ├─ data             (actual index; read by seeking back)
 *     └─ data_info XML    → blockCount
 */
cmdx_key_section *cmdx_key_section_read_v3(FILE *fp, cmdx_meta *meta) {
    if (!fp || !meta) {
        return NULL;
    }

    cmdx_unit_info key_unit_info = cmdx_unit_info_read(fp);
    if (!key_unit_info.valid ||
        key_unit_info.unit_type != CMDX_V3_UNIT_TYPE_KEY) {
        return NULL;
    }

    cmdx_key_section *key_sec = calloc(1, sizeof(cmdx_key_section));
    if (!key_sec) {
        return NULL;
    }

    cmdx_data *key_unit_data_info = NULL;
    cmdx_data *key_block_index_unit_data_info = NULL;
    cmdx_data *key_block_index_unit_data = NULL;
    long cur_pos = -1;
    long end_pos = -1;

    long key_unit_offset = ftell(fp);
    if (key_unit_offset == -1) {
        goto cleanup;
    }
    key_sec->block_offset_in_file = key_unit_offset;

    /* ═══════════════════════════════════════════════════════════════════
     * KEY unit data_info
     *
     *   Read the data_info XML from the KEY unit to extract keyCount.
     * ═══════════════════════════════════════════════════════════════════ */

    // Skip the unit's data, then read data_info XML
    if (fseek(fp, key_unit_info.data_section_length, SEEK_CUR) != 0) {
        goto cleanup;
    }

    key_unit_data_info = cmdx_storage_block_read_v3(fp, meta);
    if (!key_unit_data_info) {
        goto cleanup;
    }

    if (cmdx_xml_get_attr_uint64((char *)key_unit_data_info->data, "keyCount",
                               &key_sec->key_count) != 0) {
        goto cleanup;
    }

    cmdx_data_free_deep(key_unit_data_info);
    key_unit_data_info = NULL;

    /* ═══════════════════════════════════════════════════════════════════
     * KEY_BLOCK_INDEX unit data_info
     *
     *   Read the KEY_BLOCK_INDEX unit header, skip its data,
     *   then read its data_info XML to extract blockCount.
     *   Save cur_pos / end_pos for seeking back to read the actual index.
     * ═══════════════════════════════════════════════════════════════════ */

    cmdx_unit_info key_block_index_unit_info = cmdx_unit_info_read(fp);
    if (!key_block_index_unit_info.valid ||
        key_block_index_unit_info.unit_type != CMDX_V3_UNIT_TYPE_KEY_BLOCK_INDEX) {
        goto cleanup;
    }

    cur_pos = ftell(fp);
    if (cur_pos == -1) {
        goto cleanup;
    }

    // Skip the unit's data, then read data_info XML
    if (fseek(fp, key_block_index_unit_info.data_section_length, SEEK_CUR) != 0) {
        goto cleanup;
    }

    key_block_index_unit_data_info = cmdx_storage_block_read_v3(fp, meta);
    if (!key_block_index_unit_data_info) {
        goto cleanup;
    }

    end_pos = ftell(fp);
    if (end_pos == -1) {
        goto cleanup;
    }

    if (cmdx_xml_get_attr_uint64((char *)key_block_index_unit_data_info->data,
                               "blockCount", &key_sec->block_count) != 0) {
        goto cleanup;
    }

    cmdx_data_free_deep(key_block_index_unit_data_info);
    key_block_index_unit_data_info = NULL;

    if (key_sec->block_count == 0 || key_sec->key_count == 0) {
        goto cleanup;
    }

    /* ═══════════════════════════════════════════════════════════════════
     * read and parse the index unit's actual data
     *
     *   Seek back to cur_pos and read the KEY_BLOCK_INDEX unit's full
     *   decoded data.  This contains the block index entries describing
     *   each key data block (first/last key, compressed size, etc.).
     * ═══════════════════════════════════════════════════════════════════ */

    if (fseek(fp, cur_pos, SEEK_SET) != 0) {
        goto cleanup;
    }

    key_block_index_unit_data = cmdx_storage_block_read_v3(fp, meta);
    if (!key_block_index_unit_data) {
        goto cleanup;
    }

    if (parse_key_block_index_entries(key_sec, meta, key_block_index_unit_data->data,
                                      key_block_index_unit_data->length) != 0) {
        goto cleanup;
    }

    cmdx_data_free_deep(key_block_index_unit_data);
    key_block_index_unit_data = NULL;

    // Restore file position for subsequent reads
    if (fseek(fp, end_pos, SEEK_SET) != 0) {
        goto cleanup;
    }

    return key_sec;

cleanup:
    cmdx_data_free_deep(key_unit_data_info);
    cmdx_data_free_deep(key_block_index_unit_data_info);
    cmdx_data_free_deep(key_block_index_unit_data);
    cmdx_key_section_free(key_sec);
    return NULL;
}

void cmdx_key_section_free(cmdx_key_section *key_sec) {
    if (!key_sec) {
        return;
    }

    if (key_sec->block_indexes) {
        for (uint64_t i = 0; i < key_sec->block_count; i++) {
            free(key_sec->block_indexes[i].first_key);
            free(key_sec->block_indexes[i].last_key);
            free(key_sec->block_indexes[i].first_sort_key);
            free(key_sec->block_indexes[i].last_sort_key);
        }
        free(key_sec->block_indexes);
    }

    free(key_sec);
}

// ============================================================
// Public: binary search
// ============================================================

cmdx_key_block_index *
cmdx_key_block_index_bsearch_first(cmdx_key_section *key_sec,
                                   cmdx_meta *meta, const char *key,
                                   cmdx_icu_collator *collator, bool prefix) {
    if (!key_sec || !key || !key_sec->block_indexes) {
        return NULL;
    }
    if (key_sec->block_count == 0) {
        return NULL;
    }

    cmdx_data *sort_key_data = cmdx_sort_key_data_create(key, meta);
    cmdx_key_block_index *result =
        cmdx_key_block_index_bsearch_first_by_sort_key(key_sec, meta, key,
                                                       sort_key_data, collator, prefix);
    cmdx_data_free_deep(sort_key_data);
    return result;
}

cmdx_key_entry *
cmdx_key_entry_bsearch_first(cmdx_key_block *key_block,
                             cmdx_meta *meta, const char *key,
                             cmdx_icu_collator *collator, bool prefix) {
    if (!key_block || !key || !key_block->key_entries) {
        return NULL;
    }
    if (key_block->key_entry_count == 0) {
        return NULL;
    }

    cmdx_data *sort_key_data = cmdx_sort_key_data_create(key, meta);
    cmdx_key_entry *result =
        cmdx_key_entry_bsearch_first_by_sort_key(key_block, meta, key,
                                                  sort_key_data, collator, prefix);
    cmdx_data_free_deep(sort_key_data);
    return result;
}

// ============================================================
// Public: key comparison
// ============================================================

const char *cmdx_key_entry_get_key(const cmdx_key_entry *key_entry) {
    return key_entry ? key_entry->key : NULL;
}

int cmdx_key_cmp(const char *k1, const uint8_t *sort_k1,
                 const size_t sort_k1_len, const char *k2,
                 const uint8_t *sort_k2, const size_t sort_k2_len,
                 bool prefix, cmdx_meta *meta, cmdx_icu_collator *collator) {
    if (cmdx_is_v3(meta)) {
        return cmdx_icu_cmp(collator, k1, k2, prefix);
    } else {
        return sort_key_cmp(sort_k1, sort_k1_len, sort_k2, sort_k2_len, prefix);
    }
}

// ============================================================
// Public: key block parse
// ============================================================

cmdx_key_block *
cmdx_key_block_read(FILE *fp, cmdx_meta *meta,
                     cmdx_key_block_index *key_block_index) {
    cmdx_data *block_data = NULL;

    if (cmdx_is_v1v2(meta)) {
        block_data = cmdx_storage_block_read_v1v2(fp, meta, key_block_index->comp_size,
                                         key_block_index->decomp_size);
    } else {
        block_data = cmdx_storage_block_read_v3(fp, meta);
    }
    if (!block_data) {
        return NULL;
    }

    cmdx_key_block *key_block = (cmdx_key_block *)calloc(1, sizeof(cmdx_key_block));
    if (!key_block) {
        free(block_data);
        return NULL;
    }

    const char *key_name = key_block_index->first_key ? key_block_index->first_key : "unknown";
    char name_buf[128];
    snprintf(name_buf, sizeof(name_buf), "key_block_%s", key_name);
    uobject_init(&key_block->obj, &ud_mdict_key_block_type, name_buf);

    uint64_t entry_count = key_block_index->entry_count;
    key_block->key_entries =
        (cmdx_key_entry **)calloc(entry_count, sizeof(cmdx_key_entry *));
    if (!key_block->key_entries) {
        free(block_data);
        free(key_block);
        return NULL;
    }

    key_block->key_entry_count = entry_count;

    size_t offset = 0;
    size_t block_size = (size_t)key_block_index->decomp_size;
    uint64_t i = 0;

    for (i = 0; i < entry_count; i++) {
        key_block->key_entries[i] = (cmdx_key_entry *)calloc(1, sizeof(cmdx_key_entry));
        if (!key_block->key_entries[i]) {
            goto cleanup;
        }

        cmdx_key_entry *key_entry = key_block->key_entries[i];

        if (i > 0) {
            key_block->key_entries[i - 1]->next = key_entry;
        }

        // Read content_logical_offset
        if (cmdx_is_v2(meta) || cmdx_is_v3(meta)) {
            read_uint64_be(block_data->data + offset, block_size - offset,
                           &key_entry->content_logical_offset);
            offset += 8;
        } else {
            uint32_t tmp;
            read_uint32_be(block_data->data + offset, block_size - offset, &tmp);
            key_entry->content_logical_offset = tmp;
            offset += 4;
        }

        // Read null-terminated key string
        size_t key_start = offset;
        size_t terminator_size = meta->is_utf16 ? 2 : 1;

        if (meta->is_utf16) {
            while (offset + 1 < block_size) {
                if (block_data->data[offset] == 0 &&
                    block_data->data[offset + 1] == 0) {
                    offset += 2;
                    break;
                }
                offset += 2;
            }
        } else {
            while (offset < block_size) {
                if (block_data->data[offset] == '\0') {
                    offset += 1;
                    break;
                }
                offset++;
            }
        }

        if (offset > block_size) {
            goto cleanup;
        }

        size_t key_raw_len = offset - key_start - terminator_size;

        key_entry->key_raw = (uint8_t *)malloc(key_raw_len);
        if (!key_entry->key_raw) {
            goto cleanup;
        }
        memcpy(key_entry->key_raw, block_data->data + key_start, key_raw_len);
        key_entry->key_raw_len = key_raw_len;

        if (cmdx_encoding_to_utf8(key_entry->key_raw, key_raw_len,
                                     meta->encoding, &key_entry->key) != 0) {
            free(key_entry->key_raw);
            key_entry->key_raw = NULL;
            goto cleanup;
        }

        uobject_init(&key_entry->obj, &ud_mdict_key_entry_type, key_entry->key);

        cmdx_get_sort_key(key_entry->key_raw, key_entry->key_raw_len, meta,
                     &key_entry->sort_key, &key_entry->sort_key_len);
    }

    free(block_data);
    return key_block;

cleanup:
    if (key_block) {
        if (key_block->key_entries) {
            for (uint64_t j = 0; j < i; j++) {
                if (key_block->key_entries[j]) {
                    uobject_release(&key_block->key_entries[j]->obj);
                }
            }
            free(key_block->key_entries);
        }
        uobject_release(&key_block->obj);
    }
    free(block_data);
    return NULL;
}

// ============================================================
// Static: binary search (by pre-computed sort key)
// ============================================================

static cmdx_key_block_index *cmdx_key_block_index_bsearch_first_by_sort_key(
    cmdx_key_section *key_sec, cmdx_meta *meta, const char *key,
    const cmdx_data *sort_key_data, cmdx_icu_collator *collator, bool prefix) {
    uint64_t left = 0;
    uint64_t right = key_sec->block_count;
    cmdx_key_block_index *found = NULL;

    while (left < right) {
        uint64_t mid = left + (right - left) / 2;
        cmdx_key_block_index *mid_index = &key_sec->block_indexes[mid];

        int cmp = cmdx_key_block_index_cmp(key, sort_key_data, mid_index,
                                               meta, collator, prefix);
        if (cmp == 0) {
            found = mid_index;
            right = mid;
        } else if (cmp < 0) {
            if (mid == 0) break;
            right = mid;
        } else {
            left = mid + 1;
        }
    }

    return found;
}

static cmdx_key_entry *cmdx_key_entry_bsearch_first_by_sort_key(
    cmdx_key_block *key_block, cmdx_meta *meta, const char *key,
    const cmdx_data *sort_key_data, cmdx_icu_collator *collator, bool prefix) {
    size_t left = 0;
    size_t right = key_block->key_entry_count;
    cmdx_key_entry *found = NULL;

    while (left < right) {
        size_t mid = left + (right - left) / 2;
        cmdx_key_entry *mid_entry = key_block->key_entries[mid];

        int cmp = cmdx_key_cmp(key, sort_key_data->data, sort_key_data->length,
                               mid_entry->key, mid_entry->sort_key,
                               mid_entry->sort_key_len, prefix, meta, collator);
        if (cmp == 0) {
            found = mid_entry;
            right = mid;
        } else if (cmp < 0) {
            if (mid == 0) break;
            right = mid;
        } else {
            left = mid + 1;
        }
    }

    return found;
}

// ============================================================
// Static: key block index helpers
// ============================================================

static int cmdx_key_block_index_cmp(const char *key,
                                        const cmdx_data *sort_key_data,
                                        const cmdx_key_block_index *index,
                                        cmdx_meta *meta, cmdx_icu_collator *collator, bool prefix) {
    if (!sort_key_data || !index) {
        return 0;
    }

    if (index->first_sort_key) {
        int cmp_first = cmdx_key_cmp(
            key, sort_key_data->data, sort_key_data->length, index->first_key,
            index->first_sort_key, index->first_sort_key_len, prefix, meta, collator);
        if (cmp_first < 0) return -1;
    }

    if (index->last_sort_key) {
        int cmp_last = cmdx_key_cmp(
            key, sort_key_data->data, sort_key_data->length, index->last_key,
            index->last_sort_key, index->last_sort_key_len, prefix, meta, collator);
        if (cmp_last > 0) return 1;
    }

    return 0;
}

static int sort_key_cmp(const uint8_t *bytes1, size_t len1,
                        const uint8_t *bytes2, size_t len2, bool prefix) {
    if (bytes1 == NULL && bytes2 == NULL) {
        return 0;
    }
    if (bytes1 == NULL) {
        return -1;
    }
    if (bytes2 == NULL) {
        return 1;
    }

    size_t min_len = (len1 < len2) ? len1 : len2;
    int cmp = memcmp(bytes1, bytes2, min_len);
    if (cmp != 0) {
        return cmp;
    }

    if (prefix) {
        return (len1 <= len2) ? 0 : 1;
    }

    if (len1 < len2) return -1;
    if (len1 > len2) return 1;
    return 0;
}

/*
 * Parse all key block index entries from the decompressed index buffer.
 * Each entry describes one compressed key block (first/last key, sizes, offsets).
 */
static int parse_key_block_index_entries(cmdx_key_section *key_sec,
                                         cmdx_meta *meta,
                                         uint8_t *index_buf,
                                         uint64_t index_len) {
    if (!key_sec || !meta || !index_buf || index_len == 0) {
        return -1;
    }

    uint64_t entry_count_acc = 0;
    long block_offset = key_sec->block_offset_in_file;

    size_t count = (size_t)key_sec->block_count;
    cmdx_key_block_index *indexes = calloc(count, sizeof(cmdx_key_block_index));
    if (!indexes) {
        return -1;
    }

    size_t offset = 0;
    size_t i = 0;
    while (i < count && offset < (size_t)index_len) {
        int result = key_block_index_init(&indexes[i], index_buf,
                                          (size_t)index_len, &offset, meta);
        if (result != 0) {
            for (size_t j = 0; j <= i; j++) {
                free(indexes[j].first_key);
                free(indexes[j].last_key);
            }
            free(indexes);
            return -1;
        }

        indexes[i].offset_in_file = block_offset;
        block_offset += indexes[i].comp_size;
        entry_count_acc += indexes[i].entry_count;
        i++;
    }

    if (i != count) {
        // Parsed fewer entries than expected
    }

    if (entry_count_acc != key_sec->key_count) {
        // Total entry count mismatch
    }

    key_sec->block_indexes = indexes;
    return 0;
}

static int key_block_index_init(cmdx_key_block_index *index, uint8_t *buf,
                                size_t buf_len, size_t *offset,
                                cmdx_meta *meta) {
    if (!index || !buf || !offset || !meta || *offset >= buf_len) {
        return -1;
    }

    index->first_key = NULL;
    index->last_key = NULL;

    uint8_t *first_key_raw = NULL;
    uint8_t *last_key_raw = NULL;
    size_t first_key_raw_len = 0;
    size_t last_key_raw_len = 0;

    if (cmdx_is_v2(meta)) {
        if (!read_uint64_be(buf + *offset, buf_len - *offset, &index->entry_count))
            return -1;
        *offset += 8;

        if (key_block_index_read_key(buf, buf_len, offset, meta, &first_key_raw, &first_key_raw_len) != 0)
            return -1;
        if (key_block_index_read_key(buf, buf_len, offset, meta, &last_key_raw, &last_key_raw_len) != 0) {
            free(first_key_raw);
            return -1;
        }

        if (!read_uint64_be(buf + *offset, buf_len - *offset, &index->comp_size))
            return -1;
        *offset += 8;
        if (!read_uint64_be(buf + *offset, buf_len - *offset, &index->decomp_size))
            return -1;
        *offset += 8;
    } else {
        uint32_t tmp;
        if (!read_uint32_be(buf + *offset, buf_len - *offset, &tmp))
            return -1;
        index->entry_count = tmp;
        *offset += 4;

        if (key_block_index_read_key(buf, buf_len, offset, meta, &first_key_raw, &first_key_raw_len) != 0)
            return -1;
        if (key_block_index_read_key(buf, buf_len, offset, meta, &last_key_raw, &last_key_raw_len) != 0) {
            free(first_key_raw);
            return -1;
        }

        if (!read_uint32_be(buf + *offset, buf_len - *offset, &tmp))
            return -1;
        index->comp_size = tmp;
        *offset += 4;
        if (!read_uint32_be(buf + *offset, buf_len - *offset, &tmp))
            return -1;
        index->decomp_size = tmp;
        *offset += 4;
    }

    cmdx_get_sort_key(first_key_raw, first_key_raw_len, meta,
                 &index->first_sort_key, &index->first_sort_key_len);
    cmdx_get_sort_key(last_key_raw, last_key_raw_len, meta,
                 &index->last_sort_key, &index->last_sort_key_len);

    if (cmdx_encoding_to_utf8(first_key_raw, first_key_raw_len, meta->encoding,
                                 &index->first_key) != 0) {
        free(first_key_raw);
        free(last_key_raw);
        return -1;
    }
    if (cmdx_encoding_to_utf8(last_key_raw, last_key_raw_len, meta->encoding,
                                 &index->last_key) != 0) {
        free(first_key_raw);
        free(last_key_raw);
        return -1;
    }

    free(first_key_raw);
    free(last_key_raw);
    return 0;
}

static int key_block_index_read_key(uint8_t *buf, size_t buf_len,
                                    size_t *offset, cmdx_meta *meta,
                                    uint8_t **out_key_raw,
                                    size_t *out_key_raw_len) {
    if (!buf || !offset || !meta || *offset >= buf_len) {
        return -1;
    }

    uint16_t length;
    if (cmdx_is_v2(meta) || cmdx_is_v3(meta)) {
        if (!read_uint16_be(buf + *offset, buf_len - *offset, &length)) {
            return -1;
        }
        *offset += 2;
    } else {
        uint8_t tmp_length;
        if (!read_uint8(buf + *offset, buf_len - *offset, &tmp_length)) {
            return -1;
        }
        *offset += 1;
        length = tmp_length;
    }

    size_t terminator_size = cmdx_is_v1(meta) ? 0 : (meta->is_utf16 ? 2 : 1);
    if (meta->is_utf16) {
        length *= 2;
    }

    size_t total_len = length + terminator_size;
    if (*offset + total_len > buf_len) {
        return -1;
    }

    *out_key_raw = malloc(length);
    if (!*out_key_raw) {
        return -1;
    }

    memcpy(*out_key_raw, buf + *offset, length);
    *out_key_raw_len = length;
    *offset += total_len;

    return 0;
}

// ============================================================
// Static: object release
// ============================================================

static void ud_mdict_key_entry_release(uobject *obj) {
    cmdx_key_entry *key_entry = uobject_cast(obj, cmdx_key_entry, obj);
    if (!key_entry) {
        return;
    }

    free(key_entry->key);
    free(key_entry->key_raw);
    free(key_entry->sort_key);
    free(key_entry);
}

static void ud_mdict_key_block_release(uobject *obj) {
    cmdx_key_block *key_block = uobject_cast(obj, cmdx_key_block, obj);
    if (!key_block) {
        return;
    }

    if (key_block->key_entries) {
        for (size_t i = 0; i < key_block->key_entry_count; i++) {
            if (key_block->key_entries[i]) {
                uobject_release(&key_block->key_entries[i]->obj);
            }
        }
        free(key_block->key_entries);
    }

    free(key_block);
}
