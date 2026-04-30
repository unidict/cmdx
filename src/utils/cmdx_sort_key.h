//
//  cmdx_sort_key.h
//  libcmdx
//
//  Created by kejinlu on 2025/12/19.
//

#ifndef cmdx_sort_key_h
#define cmdx_sort_key_h

#include "cmdx_meta.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "cmdx_types.h"

#ifdef __cplusplus
extern "C" {
#endif

cmdx_data *cmdx_sort_key_data_create(const char *key, cmdx_meta *meta);

bool cmdx_get_sort_key(const uint8_t *key, size_t key_len, const cmdx_meta *meta,
                       uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* cmdx_sort_key_h */
