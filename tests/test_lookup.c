//
//  test_lookup.c
//  libcmdx tests
//

#include "test_platform.h"
#include "unity.h"
#include "cmdx_key_section.h"
#include "cmdx_reader.h"
#include <string.h>

static cmdx_reader *g_reader = NULL;

static void setUp_lookup(void) {
    const char *path = test_find_mdx_path();
    g_reader = path ? cmdx_reader_open(path, NULL) : NULL;
}

static void tearDown_lookup(void) {
    if (g_reader) {
        cmdx_reader_close(g_reader);
        g_reader = NULL;
    }
}

static void test_lookup_key_entries_null_args(void) {
    cmdx_key_entry_list *result =
        cmdx_get_key_entries_by_key(NULL, "hello", 1, false);
    TEST_ASSERT_NULL(result);

    setUp_lookup();
    TEST_ASSERT_NOT_NULL(g_reader);
    result = cmdx_get_key_entries_by_key(g_reader, NULL, 1, false);
    TEST_ASSERT_NULL(result);
    tearDown_lookup();
}

static void test_lookup_key_entries_nonexistent(void) {
    setUp_lookup();
    TEST_ASSERT_NOT_NULL(g_reader);

    cmdx_key_entry_list *result =
        cmdx_get_key_entries_by_key(g_reader, "zzzznotaword", 1, false);
    TEST_ASSERT_NULL(result);
    tearDown_lookup();
}

static void test_lookup_hello_exact(void) {
    setUp_lookup();
    TEST_ASSERT_NOT_NULL(g_reader);

    cmdx_key_entry_list *result =
        cmdx_get_key_entries_by_key(g_reader, "hello", 1, false);
    TEST_ASSERT_NOT_NULL(result);
    TEST_ASSERT_EQUAL_size_t(1, result->count);
    TEST_ASSERT_NOT_NULL(result->items[0]);
    TEST_ASSERT_EQUAL_STRING("hello", cmdx_key_entry_get_key(result->items[0]));

    cmdx_key_entry_list_free(result);
    tearDown_lookup();
}

static void test_lookup_content_hello(void) {
    setUp_lookup();
    TEST_ASSERT_NOT_NULL(g_reader);

    cmdx_data_list *result =
        cmdx_get_content_records_by_key(g_reader, "hello", 1, false);
    TEST_ASSERT_NOT_NULL(result);
    TEST_ASSERT_EQUAL_size_t(1, result->count);
    TEST_ASSERT_NOT_NULL(result->items[0]->data);
    TEST_ASSERT_TRUE(result->items[0]->length > 0);

    // Content is UTF-16LE encoded, starts with backtick marker `1`hello`2`
    // Verify the content contains the Italian translations
    // "ciao" in UTF-16LE = 63 00 69 00 61 00 6f 00
    const uint8_t ciao_utf16[] = {0x63, 0x00, 0x69, 0x00, 0x61, 0x00, 0x6f, 0x00};
    bool found_ciao = false;
    for (size_t i = 0; i + sizeof(ciao_utf16) <= result->items[0]->length; i++) {
        if (memcmp(result->items[0]->data + i, ciao_utf16, sizeof(ciao_utf16)) == 0) {
            found_ciao = true;
            break;
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(found_ciao,
                             "Content for 'hello' should contain 'ciao'");

    cmdx_data_list_free(result);
    tearDown_lookup();
}

static void test_lookup_content_by_key_entry(void) {
    setUp_lookup();
    TEST_ASSERT_NOT_NULL(g_reader);

    cmdx_key_entry_list *indexes =
        cmdx_get_key_entries_by_key(g_reader, "house", 1, false);
    TEST_ASSERT_NOT_NULL(indexes);
    TEST_ASSERT_EQUAL_size_t(1, indexes->count);

    cmdx_data *record =
        cmdx_get_content_record_by_key_entry(g_reader, indexes->items[0]);
    TEST_ASSERT_NOT_NULL(record);
    TEST_ASSERT_TRUE(record->length > 0);
    TEST_ASSERT_NOT_NULL(record->data);

    // "house" definition should contain "casa" in UTF-16LE
    // "casa" in UTF-16LE = 63 00 61 00 73 00 61 00
    const uint8_t casa_utf16[] = {0x63, 0x00, 0x61, 0x00, 0x73, 0x00, 0x61, 0x00};
    bool found_casa = false;
    for (size_t i = 0; i + sizeof(casa_utf16) <= record->length; i++) {
        if (memcmp(record->data + i, casa_utf16, sizeof(casa_utf16)) == 0) {
            found_casa = true;
            break;
        }
    }
    TEST_ASSERT_TRUE_MESSAGE(found_casa,
                             "Content for 'house' should contain 'casa'");

    cmdx_data_free_deep(record);
    cmdx_key_entry_list_free(indexes);
    tearDown_lookup();
}

static void test_lookup_content_null_args(void) {
    cmdx_data_list *result =
        cmdx_get_content_records_by_key(NULL, "hello", 1, false);
    TEST_ASSERT_NULL(result);
}

void run_lookup_tests(void) {
    printf("--- Lookup Tests ---\n");
    RUN_TEST(test_lookup_key_entries_null_args);
    RUN_TEST(test_lookup_key_entries_nonexistent);
    RUN_TEST(test_lookup_hello_exact);
    RUN_TEST(test_lookup_content_hello);
    RUN_TEST(test_lookup_content_by_key_entry);
    RUN_TEST(test_lookup_content_null_args);
}
