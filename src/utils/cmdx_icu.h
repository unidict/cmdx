//
//  cmdx_icu.h
//  libcmdx
//
//  Created by kejinlu on 2025/12/25.
//

#ifndef cmdx_icu_h
#define cmdx_icu_h

#include <stdio.h>
#include <unicode/ucol.h>
#include "cmdx_types.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct UCollator cmdx_icu_collator;

cmdx_icu_collator *cmdx_icu_collator_open(char *locale);
void cmdx_icu_collator_close(cmdx_icu_collator *collator);

int cmdx_icu_cmp(cmdx_icu_collator *collator, const char *s1, const char *s2, bool prefix);

char* cmdx_generate_locale_id(const char* encoding_label, int key_case_sensitive, int strip_key);

#ifdef __cplusplus
}
#endif

#endif /* cmdx_icu_h */
