//
//  cmdx_icu.c
//  libcmdx
//
//  Created by kejinlu on 2025/12/25.
//

#include "cmdx_icu.h"
#include <string.h>
#include <stdlib.h>
#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif
#include <unicode/ustring.h>
#include <unicode/ubrk.h>

cmdx_icu_collator *cmdx_icu_collator_open(char *locale) {
    UErrorCode status = U_ZERO_ERROR;

    // Create Chinese locale collator
    UCollator* collator = ucol_open("zh_CN", &status);
    if (U_FAILURE(status)) {
        printf("Failed to create collator: %s\n", u_errorName(status));
        return NULL;
    }
    return collator;
}

void cmdx_icu_collator_close(cmdx_icu_collator *collator) {
    ucol_close(collator);
}

// Helper: count grapheme clusters in a UTF-16 string
static int32_t count_grapheme_clusters(const UChar *text, int32_t len) {
    UErrorCode status = U_ZERO_ERROR;
    UBreakIterator *bi = ubrk_open(UBRK_CHARACTER, "root", text, len, &status);
    if (U_FAILURE(status)) {
        ubrk_close(bi);
        return -1;
    }

    int32_t count = 0;
    ubrk_first(bi);  // Move to first boundary
    while (ubrk_next(bi) != UBRK_DONE) {
        count++;
    }

    ubrk_close(bi);
    return count;
}

// Helper: count total grapheme clusters and find the n-th boundary position
// Optimized: single pass instead of two separate traversals
static void count_and_find_boundary(const UChar *text, int32_t len, int32_t n,
                                     int32_t *out_total_count,
                                     int32_t *out_nth_boundary) {
    UErrorCode status = U_ZERO_ERROR;
    UBreakIterator *bi = ubrk_open(UBRK_CHARACTER, "root", text, len, &status);
    if (U_FAILURE(status)) {
        *out_total_count = -1;
        *out_nth_boundary = -1;
        ubrk_close(bi);
        return;
    }

    int32_t count = 0;
    int32_t boundary = len;  // Default to full string length
    int32_t pos;

    ubrk_first(bi);  // Move to first boundary

    // Iterate all boundaries
    while ((pos = ubrk_next(bi)) != UBRK_DONE) {
        count++;
        // When count == n, pos is the end position of the n-th grapheme cluster
        if (count == n) {
            boundary = pos;
        }
    }

    *out_total_count = count;
    *out_nth_boundary = boundary;  // If n exceeds total count, boundary stays at len

    ubrk_close(bi);
}

// Keep find_nth_grapheme_boundary for other use cases if needed
static int32_t find_nth_grapheme_boundary(const UChar *text, int32_t len, int32_t n) {
    int32_t total_count, boundary;
    count_and_find_boundary(text, len, n, &total_count, &boundary);
    return boundary;
}

int cmdx_icu_cmp(cmdx_icu_collator *collator, const char *s1, const char *s2, bool prefix){
    // Fast path for NULL pointers
    if (s1 == s2) return 0;        // Both NULL or same pointer
    if (s1 == NULL) return -1;     // NULL < non-NULL
    if (s2 == NULL) return 1;      // non-NULL > NULL

    UErrorCode status = U_ZERO_ERROR;

    if (!prefix) {
        // Exact match
        UCollationResult result = ucol_strcollUTF8(collator, s1, -1, s2, -1, &status);

        if (U_FAILURE(status)) {
            return -2;  // Error code indicating comparison failure
        }

        // Convert UCollationResult to strcmp-like return value
        if (result == UCOL_LESS) {
            return -1;
        } else if (result == UCOL_GREATER) {
            return 1;
        }
        return 0;  // UCOL_EQUAL
    } else {
        // Prefix match: check if s1 is a prefix of s2
        // Use ICU Break Iterator to handle grapheme clusters

        // 1. Convert strings to UTF-16
        int32_t s1_len = 0, s2_len = 0;
        UErrorCode status = U_ZERO_ERROR;

        u_strFromUTF8(NULL, 0, &s1_len, s1, -1, &status);
        if (status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status)) return -2;
        status = U_ZERO_ERROR;

        u_strFromUTF8(NULL, 0, &s2_len, s2, -1, &status);
        if (status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status)) return -2;
        status = U_ZERO_ERROR;

        UChar *s1_uchar = (UChar *)malloc((s1_len + 1) * sizeof(UChar));
        UChar *s2_uchar = (UChar *)malloc((s2_len + 1) * sizeof(UChar));

        if (!s1_uchar || !s2_uchar) {
            free(s1_uchar);
            free(s2_uchar);
            return -2;
        }

        u_strFromUTF8(s1_uchar, s1_len + 1, NULL, s1, -1, &status);
        if (U_FAILURE(status)) {
            free(s1_uchar);
            free(s2_uchar);
            return -2;
        }

        status = U_ZERO_ERROR;
        u_strFromUTF8(s2_uchar, s2_len + 1, NULL, s2, -1, &status);
        if (U_FAILURE(status)) {
            free(s1_uchar);
            free(s2_uchar);
            return -2;
        }

        // 2. Count grapheme clusters in s1
        int32_t s1_gc = count_grapheme_clusters(s1_uchar, s1_len);

        if (s1_gc < 0) {
            free(s1_uchar);
            free(s2_uchar);
            return -2;
        }

        // 3. Count s2's total clusters and find s1_gc-th boundary (optimized: single pass)
        int32_t s2_gc = 0;
        int32_t s2_boundary = 0;
        count_and_find_boundary(s2_uchar, s2_len, s1_gc, &s2_gc, &s2_boundary);

        if (s2_gc < 0) {
            free(s1_uchar);
            free(s2_uchar);
            return -2;
        }

        // 4. If s2 is longer than s1, use the truncated boundary; otherwise use full length
        const UChar *s2_to_compare = s2_uchar;
        int32_t s2_compare_len = s2_boundary;  // count_and_find_boundary handles edge cases

        // 5. Compare UTF-16 strings using ucol_strcoll
        UCollationResult result = ucol_strcoll(collator, s1_uchar, s1_len, s2_to_compare, s2_compare_len);

        free(s1_uchar);
        free(s2_uchar);

        if (result == UCOL_LESS) {
            return -1;
        } else if (result == UCOL_GREATER) {
            return 1;
        }
        return 0;  // UCOL_EQUAL
    }
}


char* cmdx_generate_locale_id(const char* encoding_label, int key_case_sensitive, int strip_key) {
    const char* base = NULL;
    const char* case_suffix = NULL;
    const char* strip_suffix = "";

    if (strcasecmp(encoding_label, "gbk") == 0 ||
        strcasecmp(encoding_label, "gb2312") == 0 ||
        strcasecmp(encoding_label, "gb18030") == 0) {
        base = "zh-Hans-u-co-pinyin";
    } else if (strcasecmp(encoding_label, "big5") == 0) {
        base = "zh-Hant-u-co-pinyin";
    } else {
        base = "en-u";
    }

    if (key_case_sensitive) {
        case_suffix = "-ks-level3";
    } else {
        case_suffix = "-ks-level2";
    }

    if (strip_key) {
        strip_suffix = "-ka-shifted";
    }

    size_t total_len = strlen(base) + strlen(case_suffix) + strlen(strip_suffix) + 1;
    char* result = (char*)malloc(total_len);

    if (result == NULL) {
        return NULL; // Memory allocation failed
    }

    // Concatenate locale ID parts
    snprintf(result, total_len, "%s%s%s", base, case_suffix, strip_suffix);

    return result;
}
