//
//  cmdx_types.h
//  libcmdx
//
//  Public types for the cmdx API.
//

#ifndef cmdx_types_h
#define cmdx_types_h

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// Data buffer
// ============================================================

typedef struct {
    uint8_t *data;
    size_t length;
} cmdx_data;

// ============================================================
// Key entry (opaque)
// ============================================================

typedef struct cmdx_key_entry cmdx_key_entry;

const char *cmdx_key_entry_get_key(const cmdx_key_entry *key_entry);

// ============================================================
// Result list types
// ============================================================

typedef struct {
    cmdx_key_entry **items;
    size_t count;
} cmdx_key_entry_list;

typedef struct {
    cmdx_data **items;
    size_t count;
} cmdx_data_list;

// ============================================================
// Cleanup
// ============================================================

void cmdx_data_free_shallow(cmdx_data *data);
void cmdx_data_free_deep(cmdx_data *data);

void cmdx_key_entry_list_free(cmdx_key_entry_list *list);
void cmdx_data_list_free(cmdx_data_list *list);

#ifdef __cplusplus
}
#endif

#endif /* cmdx_types_h */
