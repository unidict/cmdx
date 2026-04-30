//
//  cmdx_reader.h
//  libcmdx
//
//  Created by kejinlu on 2025/11/17.
//

#ifndef cmdx_reader_h
#define cmdx_reader_h

#include "cmdx_types.h"
#include "cmdx_meta.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// Reader (opaque)
// ============================================================

typedef struct cmdx_reader cmdx_reader;

cmdx_reader *cmdx_reader_open(const char *file_path, const char *device_id);
void cmdx_reader_close(cmdx_reader *reader);

// ============================================================
// Meta accessors
// ============================================================

const cmdx_meta *cmdx_reader_get_meta(const cmdx_reader *reader);
uint64_t cmdx_reader_get_key_count(const cmdx_reader *reader);

// ============================================================
// Lookup
// ============================================================

cmdx_key_entry_list *cmdx_get_key_entries_by_key(cmdx_reader *reader,
                                                  char *key, size_t max_count,
                                                  bool prefix);

cmdx_data_list *cmdx_get_content_records_by_key(cmdx_reader *reader,
                                                 char *key, size_t max_count,
                                                 bool prefix);

cmdx_data *cmdx_get_content_record_by_key_entry(cmdx_reader *reader,
                                                 cmdx_key_entry *key_entry);

// ============================================================
// Iterator
// ============================================================

typedef struct cmdx_entry_iter cmdx_entry_iter;

cmdx_entry_iter *cmdx_reader_iter_create(cmdx_reader *reader);
bool cmdx_iter_next(cmdx_entry_iter *iter);
cmdx_key_entry *cmdx_iter_current(const cmdx_entry_iter *iter);
void cmdx_iter_free(cmdx_entry_iter *iter);

#ifdef __cplusplus
}
#endif

#endif /* cmdx_reader_h */
