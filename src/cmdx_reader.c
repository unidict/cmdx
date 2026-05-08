//
//  cmdx_reader.c
//  libcmdx
//
//  Created by kejinlu on 2025/11/17.
//

#include "cmdx_reader.h"
#include "ucache.h"
#include "cmdx_meta.h"
#include "cmdx_key_section.h"
#include "cmdx_icu.h"
#include "cmdx_content_section.h"
#include <zlib.h>
#include "cmdx_crypto.h"
#include "cmdx_sort_key.h"
#include "cmdx_util.h"
#include "cmdx_endian.h"
#include <iconv.h>
#include <stdlib.h>
#include <string.h>

// ============================================================
// Reader struct definition (internal only)
// ============================================================

struct cmdx_reader {
    char *file_path;
    FILE *fp;
    cmdx_meta *meta;
    cmdx_key_section *key_section;
    cmdx_content_section *content_section;
    cmdx_icu_collator *collator;
    ucache *key_block_cache;
    ucache *content_block_cache;
};

// ============================================================
// Internal growth helper
// ============================================================

static bool list_grow(void **items, size_t *capacity, size_t elem_size,
                      size_t max_capacity) {
    size_t new_cap = *capacity * 2;
    if (new_cap > max_capacity) {
        new_cap = max_capacity;
    }
    if (new_cap <= *capacity) {
        return false;
    }
    void *new_items = realloc(*items, new_cap * elem_size);
    if (!new_items) {
        return false;
    }
    *items = new_items;
    *capacity = new_cap;
    return true;
}

// ============================================================
// Private function declarations
// ============================================================

cmdx_key_block *
key_block_get_retained(cmdx_reader *reader,
                                cmdx_key_block_index *key_block_index);

cmdx_content_block *content_block_get_retained(
    cmdx_reader *reader,
    cmdx_content_block_index *content_block_index);

// ============================================================
// Lifecycle
// ============================================================

cmdx_reader *cmdx_reader_open(const char *file_path,
                              const char *device_id) {
    // Only little-endian platforms are supported
    uint16_t endian_test = 0x0001;
    if (*(uint8_t *)&endian_test != 0x01) {
        return NULL;
    }

    if (!file_path) {
        return NULL;
    }

    cmdx_reader *reader = calloc(1, sizeof(cmdx_reader));
    if (!reader) {
        return NULL;
    }
    reader->file_path = strdup(file_path);
    if (!reader->file_path) {
        cmdx_reader_close(reader);
        return NULL;
    }
    reader->fp = fopen(reader->file_path, "rb");
    if (!reader->fp) {
        cmdx_reader_close(reader);
        return NULL;
    }

    /*
     * MDict file format structure:
     *
     *   * Meta Section
     *   * Key (keyword) Section
     *   * Content Section
     */
    reader->meta = cmdx_meta_read(reader->fp);
    if (reader->meta == NULL) {
        cmdx_reader_close(reader);
        return NULL;
    }

    // Create ICU collator for key comparison
    if (reader->meta->default_sorting_locale) {
        reader->collator = cmdx_icu_collator_open(reader->meta->default_sorting_locale);
    } else {
        char *locale_id = cmdx_generate_locale_id(
            cmdx_encoding_name(reader->meta->encoding),
            reader->meta->key_case_sensitive, reader->meta->strip_key);
        reader->collator = cmdx_icu_collator_open(locale_id);
        free(locale_id);
    }

    char *reg_code = NULL;
    if (device_id) {
        char *license_path = cmdx_path_dup_with_ext(file_path, "key");
        if (license_path) {
            reg_code = cmdx_file_read_string(license_path);
        }
        free(license_path);
    }

    if (!reg_code && reader->meta->reg_code && reader->meta->reg_code[0] != '\0') {
        reg_code = strdup(reader->meta->reg_code);
    }
    if (!reg_code && is_key_block_index_info_encrypted(reader->meta)) {
        return NULL;
    }

    /**
     Registration code derivation (realkey is the actual dictionary password):
     unsigned char realkey[CMDX_HASH128_SIZE];
     cmdx_ripemd128("xxxxx", 5, realkey);
     uint8_t derivation_key[CMDX_HASH128_SIZE];
     cmdx_ripemd128((uint8_t *)device_id, strlen(device_id), derivation_key);
     uint8_t  *reg_code = decrypt_salsa20(realkey,16, derivation_key, 128);
     */
    if (reg_code) {
        uint8_t *reg_code_bytes = NULL;
        int reg_code_bytes_len = cmdx_hex_decode(reg_code, &reg_code_bytes);
        uint8_t derivation_key[CMDX_HASH128_SIZE];
        cmdx_ripemd128_hash((uint8_t *)device_id, strlen(device_id), derivation_key);
        reader->meta->crypto_key =
            cmdx_salsa20_decrypt(reg_code_bytes, reg_code_bytes_len, derivation_key,
                            CMDX_HASH128_SIZE);
        // reg_code is hex-encoded RIPEMD-128 output, realkey length is always 128-bit
        reader->meta->crypto_key_len = CMDX_HASH128_SIZE;
        free(reg_code_bytes);
        free(reg_code);
    } else {
        if (cmdx_is_v3(reader->meta) && reader->meta->uuid) {
            char *uuid = reader->meta->uuid;
            uint8_t *output = malloc(CMDX_HASH128_SIZE);
            cmdx_fast128_hash((uint8_t *)uuid, strlen(uuid), output);
            reader->meta->crypto_key = output;
            // fast128_hash output is always 128-bit
            reader->meta->crypto_key_len = CMDX_HASH128_SIZE;
        }
    }

    if (cmdx_is_v1v2(reader->meta)) {
        reader->key_section =
            cmdx_key_section_read_v1v2(reader->fp, reader->meta);
        reader->content_section =
            cmdx_content_section_read_v1v2(reader->fp, reader->meta);
    } else {
        // V3: content section comes before key section
        reader->content_section =
            cmdx_content_section_read_v3(reader->fp, reader->meta);
        reader->key_section = cmdx_key_section_read_v3(reader->fp, reader->meta);
    }

    ucache_config cache_config = {.max_items = 16,
                                  .initial_capacity = 16,
                                  .thread_safe = true,
                                  .enable_stats = true};
    reader->key_block_cache = ucache_new(&cache_config);
    reader->content_block_cache = ucache_new(&cache_config);
    if (!reader->key_block_cache || !reader->content_block_cache) {
        cmdx_reader_close(reader);
        return NULL;
    }
    return reader;
}

void cmdx_reader_close(cmdx_reader *reader) {
    if (!reader) {
        return;
    }
    if (reader->key_block_cache) {
        ucache_free(reader->key_block_cache);
    }
    if (reader->content_block_cache) {
        ucache_free(reader->content_block_cache);
    }
    if (reader->collator) {
        cmdx_icu_collator_close(reader->collator);
    }
    if (reader->key_section) {
        cmdx_key_section_free(reader->key_section);
    }
    if (reader->content_section) {
        ud_mdict_content_section_free(reader->content_section);
    }
    if (reader->meta) {
        cmdx_meta_free(reader->meta);
    }
    if (reader->fp) {
        fclose(reader->fp);
    }
    free(reader->file_path);
    free(reader);
}

// ============================================================
// Meta accessors
// ============================================================

const cmdx_meta *cmdx_reader_get_meta(const cmdx_reader *reader) {
    return reader ? reader->meta : NULL;
}

uint64_t cmdx_reader_get_key_count(const cmdx_reader *reader) {
    if (!reader || !reader->key_section) {
        return 0;
    }
    return reader->key_section->key_count;
}

// ============================================================
// Lookup
// ============================================================

cmdx_data_list *cmdx_get_content_records_by_key(cmdx_reader *reader, char *key,
                                                 size_t max_count,
                                                 bool prefix) {
    if (!reader || !key) {
        return NULL;
    }

    // Get all matching key entries
    cmdx_key_entry_list *indexes =
        cmdx_get_key_entries_by_key(reader, key, max_count, prefix);
    if (!indexes) {
        return NULL;
    }

    cmdx_data_list *list = calloc(1, sizeof(cmdx_data_list));
    if (!list) {
        cmdx_key_entry_list_free(indexes);
        return NULL;
    }

    size_t capacity = indexes->count;
    if (capacity > 0) {
        list->items = malloc(capacity * sizeof(cmdx_data *));
        if (!list->items) {
            cmdx_key_entry_list_free(indexes);
            free(list);
            return NULL;
        }
    }

    // Fetch content record for each index
    for (size_t i = 0; i < indexes->count; i++) {
        cmdx_key_entry *key_entry = indexes->items[i];
        if (key_entry) {
            cmdx_data *record =
                cmdx_get_content_record_by_key_entry(reader, key_entry);
            if (record) {
                list->items[list->count++] = record;
            }
        }
    }

    cmdx_key_entry_list_free(indexes);
    return list;
}

cmdx_key_entry_list *cmdx_get_key_entries_by_key(cmdx_reader *reader,
                                                  char *key,
                                                  size_t max_count,
                                                  bool prefix) {
    if (!reader || !key) {
        return NULL;
    }

    cmdx_data *sort_key_data = cmdx_sort_key_data_create(key, reader->meta);

    // Binary search for the first matching key block index
    cmdx_key_block_index *key_block_index =
        cmdx_key_block_index_bsearch_first(
            reader->key_section, reader->meta, key, reader->collator, prefix);
    if (!key_block_index) {
        cmdx_data_free_deep(sort_key_data);
        return NULL;
    }
    cmdx_key_block *key_block =
        key_block_get_retained(reader, key_block_index);
    if (!key_block) {
        cmdx_data_free_deep(sort_key_data);
        return NULL;
    }
    // Binary search within the block for the first matching key entry
    cmdx_key_entry *key_entry =
        cmdx_key_entry_bsearch_first(key_block, reader->meta, key, reader->collator, prefix);
    if (!key_entry) {
        uobject_release(&key_block->obj);
        cmdx_data_free_deep(sort_key_data);
        return NULL;
    }

    // Allocate result list with initial capacity
    cmdx_key_entry_list *list = calloc(1, sizeof(cmdx_key_entry_list));
    if (!list) {
        uobject_release(&key_block->obj);
        cmdx_data_free_deep(sort_key_data);
        return NULL;
    }

    size_t capacity = 8;
    if (max_count > 0 && capacity > max_count) {
        capacity = max_count;
    }
    if (capacity > 0) {
        list->items = malloc(capacity * sizeof(cmdx_key_entry *));
        if (!list->items) {
            uobject_release(&key_block->obj);
            cmdx_data_free_deep(sort_key_data);
            free(list);
            return NULL;
        }
    }

    // Retain and add first match
    uobject_retain(&key_entry->obj);
    list->items[list->count++] = key_entry;

    // Collect subsequent matching key entries
    size_t remaining = (max_count > 0) ? max_count - 1 : SIZE_MAX;
    key_entry = key_entry->next;

    while (remaining > 0) {
        if (key_entry) {
            int cmp = cmdx_key_cmp(key, sort_key_data->data,
                                   sort_key_data->length, key_entry->key,
                                   key_entry->sort_key,
                                   key_entry->sort_key_len, prefix,
                                   reader->meta, reader->collator);
            if (cmp == 0) {
                // Grow if needed
                if (list->count >= capacity) {
                    size_t grow_max = max_count > 0 ? max_count : SIZE_MAX;
                    if (!list_grow((void **)&list->items, &capacity,
                                   sizeof(cmdx_key_entry *), grow_max)) {
                        break;
                    }
                }
                uobject_retain(&key_entry->obj);
                list->items[list->count++] = key_entry;
                remaining--;
                key_entry = key_entry->next;
            } else {
                break;
            }
        } else {
            // Reached end of current block; check next block
            cmdx_key_block_index *last_key_block_index =
                &(reader->key_section
                      ->block_indexes[reader->key_section->block_count - 1]);
            if (remaining > 0 && key_block_index < last_key_block_index) {
                key_block_index += 1;

                if (key_block) {
                    uobject_release(&key_block->obj);
                    key_block = NULL;
                }
                key_block =
                    key_block_get_retained(reader, key_block_index);
                if (key_block) {
                    key_entry = key_block->key_entries[0];
                }
            } else {
                break;
            }
        }
    }

    // Each element in list holds its own reference; safe to release key_block
    if (key_block) {
        uobject_release(&key_block->obj);
    }
    cmdx_data_free_deep(sort_key_data);
    return list;
}

/**
 * Get a single content record by key entry.
 */
cmdx_data *cmdx_get_content_record_by_key_entry(cmdx_reader *reader,
                                                 cmdx_key_entry *key_entry) {
    if (!reader || !key_entry) {
        return NULL;
    }

    uint64_t content_offset = key_entry->content_logical_offset;

    // Binary search for the content block index containing this offset
    cmdx_content_block_index *content_block_index =
        ud_mdict_content_block_index_bsearch(reader->content_section,
                                             content_offset);
    if (!content_block_index) {
        return NULL;
    }

    // Get content block (cached)
    cmdx_content_block *content_block =
        content_block_get_retained(reader, content_block_index);
    if (!content_block) {
        return NULL;
    }

    // Extract record data from the content block
    cmdx_data *record = cmdx_content_record_extract(
        key_entry, content_block_index, content_block);

    // Release content block reference
    uobject_release(&content_block->obj);

    return record;
}

// ============================================================
// Result list cleanup
// ============================================================

void cmdx_key_entry_list_free(cmdx_key_entry_list *list) {
    if (!list) {
        return;
    }
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i]) {
            uobject_release(&list->items[i]->obj);
        }
    }
    free(list->items);
    free(list);
}

void cmdx_data_list_free(cmdx_data_list *list) {
    if (!list) {
        return;
    }
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i]) {
            cmdx_data_free_deep(list->items[i]);
        }
    }
    free(list->items);
    free(list);
}

// ============================================================
// Private functions
// ============================================================

cmdx_key_block *
key_block_get_retained(cmdx_reader *reader,
                                cmdx_key_block_index *key_block_index) {
    if (!reader || !key_block_index) {
        return NULL;
    }

    // Look up in cache and retain if found
    uobject *obj = NULL;
    ucache_get_retain(reader->key_block_cache,
                      &(key_block_index->offset_in_file),
                      sizeof(key_block_index->offset_in_file), &obj);

    cmdx_key_block *key_block = NULL;
    if (obj) {
        // Cache hit
        key_block = uobject_cast(obj, cmdx_key_block, obj);
    } else {
        // Cache miss, read and parse from file
        if (fseek(reader->fp, (long)key_block_index->offset_in_file,
                  SEEK_SET) != 0) {
            return NULL;
        }
        key_block = cmdx_key_block_read(reader->fp, reader->meta,
                                        key_block_index);
        if (!key_block) {
            return NULL;
        }
        // Store in cache
        ucache_set(reader->key_block_cache,
                   &(key_block_index->offset_in_file),
                   sizeof(key_block_index->offset_in_file), &key_block->obj);
    }

    return key_block;
}

cmdx_content_block *content_block_get_retained(
    cmdx_reader *reader,
    cmdx_content_block_index *content_block_index) {
    if (!reader || !content_block_index) {
        return NULL;
    }

    // Look up in cache and retain if found
    uobject *obj = NULL;
    ucache_get_retain(reader->content_block_cache,
                      &content_block_index->logical_offset,
                      sizeof(content_block_index->logical_offset), &obj);

    cmdx_content_block *content_block = NULL;
    if (obj) {
        // Cache hit
        content_block = uobject_cast(obj, cmdx_content_block, obj);
    } else {
        // Cache miss, read and parse from file
        content_block = cmdx_content_block_read(
            reader->fp, reader->meta, content_block_index);
        if (!content_block) {
            return NULL;
        }
        // Store in cache
        ucache_set(reader->content_block_cache,
                   &content_block_index->logical_offset,
                   sizeof(content_block_index->logical_offset),
                   &content_block->obj);
    }

    return content_block;
}

// ============================================================
// Iterator
// ============================================================

struct cmdx_entry_iter {
    cmdx_reader *reader;
    uint64_t block_index;
    cmdx_key_block *key_block;
    size_t entry_index;
    cmdx_key_entry *current;
};

cmdx_entry_iter *cmdx_reader_iter_create(cmdx_reader *reader) {
    if (!reader || !reader->key_section) {
        return NULL;
    }
    cmdx_entry_iter *iter = calloc(1, sizeof(cmdx_entry_iter));
    if (!iter) {
        return NULL;
    }
    iter->reader = reader;
    return iter;
}

bool cmdx_iter_next(cmdx_entry_iter *iter) {
    if (!iter) {
        return false;
    }

    cmdx_key_section *key_sec = iter->reader->key_section;

    for (;;) {
        if (iter->key_block &&
            iter->entry_index < iter->key_block->key_entry_count) {
            iter->current = iter->key_block->key_entries[iter->entry_index++];
            return true;
        }

        if (iter->key_block) {
            uobject_release(&iter->key_block->obj);
            iter->key_block = NULL;
        }

        if (iter->block_index >= key_sec->block_count) {
            iter->current = NULL;
            return false;
        }

        cmdx_key_block_index *kbi =
            &key_sec->block_indexes[iter->block_index++];
        iter->key_block =
            key_block_get_retained(iter->reader, kbi);
        if (!iter->key_block) {
            iter->current = NULL;
            return false;
        }

        iter->entry_index = 0;
    }
}

cmdx_key_entry *cmdx_iter_current(const cmdx_entry_iter *iter) {
    return iter ? iter->current : NULL;
}

void cmdx_iter_free(cmdx_entry_iter *iter) {
    if (!iter) {
        return;
    }
    if (iter->key_block) {
        uobject_release(&iter->key_block->obj);
    }
    free(iter);
}