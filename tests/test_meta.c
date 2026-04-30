//
//  test_meta.c
//  libcmdx tests
//

#include "unity.h"
#include "test_platform.h"
#include "cmdx_reader.h"

static cmdx_reader *g_reader = NULL;

static void setUp_meta(void) {
    const char *path = test_find_mdx_path();
    g_reader = path ? cmdx_reader_open(path, NULL) : NULL;
}

static void tearDown_meta(void) {
    if (g_reader) {
        cmdx_reader_close(g_reader);
        g_reader = NULL;
    }
}

static void test_meta_not_null(void) {
    setUp_meta();
    TEST_ASSERT_NOT_NULL(g_reader);
    TEST_ASSERT_NOT_NULL(cmdx_reader_get_meta(g_reader));
    tearDown_meta();
}

static void test_meta_version(void) {
    setUp_meta();
    TEST_ASSERT_NOT_NULL(g_reader);
    cmdx_version v = cmdx_reader_get_meta(g_reader)->version;
    TEST_ASSERT_TRUE(v == CMDX_V1 || v == CMDX_V2 || v == CMDX_V3);
    tearDown_meta();
}

static void test_meta_encoding(void) {
    setUp_meta();
    TEST_ASSERT_NOT_NULL(g_reader);
    cmdx_encoding enc = cmdx_reader_get_meta(g_reader)->encoding;
    TEST_ASSERT_TRUE(enc >= CMDX_ENCODING_UTF8 && enc <= CMDX_ENCODING_GB18030);
    tearDown_meta();
}

static void test_meta_title_not_null(void) {
    setUp_meta();
    TEST_ASSERT_NOT_NULL(g_reader);
    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader);
    TEST_ASSERT_NOT_NULL(meta->title);
    TEST_ASSERT_TRUE(strlen(meta->title) > 0);
    tearDown_meta();
}

static void test_meta_not_encrypted(void) {
    setUp_meta();
    TEST_ASSERT_NOT_NULL(g_reader);
    TEST_ASSERT_EQUAL_UINT8(0, cmdx_reader_get_meta(g_reader)->encrypted);
    tearDown_meta();
}

static void test_meta_key_count_positive(void) {
    setUp_meta();
    TEST_ASSERT_NOT_NULL(g_reader);
    TEST_ASSERT_TRUE(cmdx_reader_get_key_count(g_reader) > 0);
    tearDown_meta();
}

void run_meta_tests(void) {
    printf("--- Meta Tests ---\n");
    RUN_TEST(test_meta_not_null);
    RUN_TEST(test_meta_version);
    RUN_TEST(test_meta_encoding);
    RUN_TEST(test_meta_title_not_null);
    RUN_TEST(test_meta_not_encrypted);
    RUN_TEST(test_meta_key_count_positive);
}
