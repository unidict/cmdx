//
//  test_dictionaries.c
//  libcmdx tests
//
//  Tests for multiple MDX dictionary files covering different
//  versions, encodings, encryption, and compression.
//

#include "test_platform.h"
#include "unity.h"
#include "cmdx_reader.h"
#include "cmdx_meta.h"
#include "cmdx_util.h"
#include <stdlib.h>
#include <string.h>

// ============================================================
// Helpers
// ============================================================

static char *content_to_utf8(const cmdx_data *record, const cmdx_meta *meta) {
    char *utf8 = NULL;
    int rc = cmdx_encoding_to_utf8(record->data, record->length,
                                    meta->encoding, &utf8);
    return (rc == 0) ? utf8 : NULL;
}

// ============================================================
// test_utf8_v2.0.mdx  (V2, UTF-8, encrypted=2)
// ============================================================

static cmdx_reader *g_reader_utf8_v2 = NULL;

static void setUp_utf8_v2(void) {
    const char *path = test_find_data_file("test_utf8_v2.0.mdx");
    g_reader_utf8_v2 = path ? cmdx_reader_open(path, NULL) : NULL;
}

static void tearDown_utf8_v2(void) {
    if (g_reader_utf8_v2) {
        cmdx_reader_close(g_reader_utf8_v2);
        g_reader_utf8_v2 = NULL;
    }
}

static void test_utf8_v2_meta(void) {
    setUp_utf8_v2();
    TEST_ASSERT_NOT_NULL(g_reader_utf8_v2);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_utf8_v2);
    TEST_ASSERT_EQUAL(CMDX_V2, meta->version);
    TEST_ASSERT_EQUAL(CMDX_ENCODING_UTF8, meta->encoding);
    TEST_ASSERT_EQUAL_UINT8(2, meta->encrypted);
    TEST_ASSERT_EQUAL_UINT64(3, cmdx_reader_get_key_count(g_reader_utf8_v2));

    tearDown_utf8_v2();
}

static void test_utf8_v2_lookup_Abc(void) {
    setUp_utf8_v2();
    TEST_ASSERT_NOT_NULL(g_reader_utf8_v2);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_utf8_v2, "Abc", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);
    TEST_ASSERT_EQUAL_STRING("Abc", cmdx_key_entry_get_key(entries->items[0]));

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_utf8_v2, "Abc", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_utf8_v2);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_NOT_NULL(strstr(utf8, "Abc"));
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_utf8_v2();
}

static void test_utf8_v2_lookup_English(void) {
    setUp_utf8_v2();
    TEST_ASSERT_NOT_NULL(g_reader_utf8_v2);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_utf8_v2, "English", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_utf8_v2, "English", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_utf8_v2);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_NOT_NULL(strstr(utf8, "English test"));
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_utf8_v2();
}

// ============================================================
// test_gbk_devid_kejinlu@gmail.com_v2.0.mdx  (V2, GBK, encrypted=3)
// ============================================================

static cmdx_reader *g_reader_gbk_v2 = NULL;

static void setUp_gbk_v2(void) {
    const char *path =
        test_find_data_file("test_gbk_devid_kejinlu@gmail.com_v2.0.mdx");
    g_reader_gbk_v2 =
        path ? cmdx_reader_open(path, "kejinlu@gmail.com") : NULL;
}

static void tearDown_gbk_v2(void) {
    if (g_reader_gbk_v2) {
        cmdx_reader_close(g_reader_gbk_v2);
        g_reader_gbk_v2 = NULL;
    }
}

static void test_gbk_v2_meta(void) {
    setUp_gbk_v2();
    TEST_ASSERT_NOT_NULL(g_reader_gbk_v2);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_gbk_v2);
    TEST_ASSERT_EQUAL(CMDX_V2, meta->version);
    TEST_ASSERT_TRUE(meta->encoding == CMDX_ENCODING_GBK ||
                     meta->encoding == CMDX_ENCODING_GB18030);
    TEST_ASSERT_EQUAL_UINT8(3, meta->encrypted);
    TEST_ASSERT_EQUAL_UINT64(3, cmdx_reader_get_key_count(g_reader_gbk_v2));

    tearDown_gbk_v2();
}

static void test_gbk_v2_lookup_Abc(void) {
    setUp_gbk_v2();
    TEST_ASSERT_NOT_NULL(g_reader_gbk_v2);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_gbk_v2, "Abc", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);
    TEST_ASSERT_EQUAL_STRING("Abc", cmdx_key_entry_get_key(entries->items[0]));

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_gbk_v2, "Abc", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_gbk_v2);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_NOT_NULL(strstr(utf8, "Abc"));
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_gbk_v2();
}

static void test_gbk_v2_lookup_chinese(void) {
    setUp_gbk_v2();
    TEST_ASSERT_NOT_NULL(g_reader_gbk_v2);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_gbk_v2, "中文", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);
    TEST_ASSERT_EQUAL_STRING("中文", cmdx_key_entry_get_key(entries->items[0]));

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_gbk_v2, "中文", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_gbk_v2);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_NOT_NULL(strstr(utf8, "中文测试"));
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_gbk_v2();
}

static void test_gbk_v2_lookup_English(void) {
    setUp_gbk_v2();
    TEST_ASSERT_NOT_NULL(g_reader_gbk_v2);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_gbk_v2, "English", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_gbk_v2, "English", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_gbk_v2);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_NOT_NULL(strstr(utf8, "English test"));
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_gbk_v2();
}

// ============================================================
// test_chinese_key_v3.0.mdx  (V3, UTF-8, no encryption)
// ============================================================

static cmdx_reader *g_reader_v3 = NULL;

static void setUp_v3(void) {
    const char *path = test_find_data_file("test_chinese_key_v3.0.mdx");
    g_reader_v3 = path ? cmdx_reader_open(path, NULL) : NULL;
}

static void tearDown_v3(void) {
    if (g_reader_v3) {
        cmdx_reader_close(g_reader_v3);
        g_reader_v3 = NULL;
    }
}

static void test_v3_meta(void) {
    setUp_v3();
    TEST_ASSERT_NOT_NULL(g_reader_v3);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_v3);
    TEST_ASSERT_EQUAL(CMDX_V3, meta->version);
    TEST_ASSERT_EQUAL(CMDX_ENCODING_UTF8, meta->encoding);
    TEST_ASSERT_EQUAL_UINT8(0, meta->encrypted);
    TEST_ASSERT_EQUAL_UINT64(9, cmdx_reader_get_key_count(g_reader_v3));

    tearDown_v3();
}

static void test_v3_lookup_chinese(void) {
    setUp_v3();
    TEST_ASSERT_NOT_NULL(g_reader_v3);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_v3, "安全", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);
    TEST_ASSERT_EQUAL_STRING("安全", cmdx_key_entry_get_key(entries->items[0]));

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_v3, "安全", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_v3);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_NOT_NULL(strstr(utf8, "安全测试"));
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_v3();
}

static void test_v3_lookup_hangzhou(void) {
    setUp_v3();
    TEST_ASSERT_NOT_NULL(g_reader_v3);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_v3, "杭州", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);
    TEST_ASSERT_EQUAL_STRING("杭州", cmdx_key_entry_get_key(entries->items[0]));

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_v3, "杭州", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_v3);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_NOT_NULL(strstr(utf8, "杭州测试"));
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_v3();
}

static void test_v3_lookup_zhichi(void) {
    setUp_v3();
    TEST_ASSERT_NOT_NULL(g_reader_v3);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_v3, "支持", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);
    TEST_ASSERT_EQUAL_STRING("支持", cmdx_key_entry_get_key(entries->items[0]));

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_v3, "支持", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_v3);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_NOT_NULL(strstr(utf8, "支持测试"));
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_v3();
}

// ============================================================
// test_chinese_key_devid_kejinlu@gmail.com_v3.0.mdx  (V3, encrypted)
// ============================================================

static cmdx_reader *g_reader_v3_enc = NULL;

static void setUp_v3_enc(void) {
    const char *path =
        test_find_data_file("test_chinese_key_devid_kejinlu@gmail.com_v3.0.mdx");
    g_reader_v3_enc =
        path ? cmdx_reader_open(path, "kejinlu@gmail.com") : NULL;
}

static void tearDown_v3_enc(void) {
    if (g_reader_v3_enc) {
        cmdx_reader_close(g_reader_v3_enc);
        g_reader_v3_enc = NULL;
    }
}

static void test_v3_enc_meta(void) {
    setUp_v3_enc();
    TEST_ASSERT_NOT_NULL(g_reader_v3_enc);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_v3_enc);
    TEST_ASSERT_EQUAL(CMDX_V3, meta->version);
    TEST_ASSERT_EQUAL(CMDX_ENCODING_UTF8, meta->encoding);
    TEST_ASSERT_EQUAL_UINT64(9, cmdx_reader_get_key_count(g_reader_v3_enc));

    tearDown_v3_enc();
}

static void test_v3_enc_lookup_anquan(void) {
    setUp_v3_enc();
    TEST_ASSERT_NOT_NULL(g_reader_v3_enc);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_v3_enc, "安全", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);
    TEST_ASSERT_EQUAL_STRING("安全", cmdx_key_entry_get_key(entries->items[0]));

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_v3_enc, "安全", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_v3_enc);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_NOT_NULL(strstr(utf8, "安全测试"));
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_v3_enc();
}

static void test_v3_enc_lookup_meili(void) {
    setUp_v3_enc();
    TEST_ASSERT_NOT_NULL(g_reader_v3_enc);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_v3_enc, "美丽", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);
    TEST_ASSERT_EQUAL_STRING("美丽", cmdx_key_entry_get_key(entries->items[0]));

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_v3_enc, "美丽", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_v3_enc);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_NOT_NULL(strstr(utf8, "美丽测试"));
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_v3_enc();
}

static void test_v3_enc_lookup_xiatian(void) {
    setUp_v3_enc();
    TEST_ASSERT_NOT_NULL(g_reader_v3_enc);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_v3_enc, "夏天", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);
    TEST_ASSERT_EQUAL_STRING("夏天", cmdx_key_entry_get_key(entries->items[0]));

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_v3_enc, "夏天", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_v3_enc);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_NOT_NULL(strstr(utf8, "夏天测试"));
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_v3_enc();
}

// ============================================================
// test_lzo.mdx  (V2, UTF-8, LZO compression, no encryption)
// ============================================================

static cmdx_reader *g_reader_lzo = NULL;

static void setUp_lzo(void) {
    const char *path = test_find_data_file("test_lzo.mdx");
    g_reader_lzo = path ? cmdx_reader_open(path, NULL) : NULL;
}

static void tearDown_lzo(void) {
    if (g_reader_lzo) {
        cmdx_reader_close(g_reader_lzo);
        g_reader_lzo = NULL;
    }
}

static void test_lzo_meta(void) {
    setUp_lzo();
    TEST_ASSERT_NOT_NULL(g_reader_lzo);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_lzo);
    TEST_ASSERT_EQUAL(CMDX_V2, meta->version);
    TEST_ASSERT_EQUAL(CMDX_ENCODING_UTF8, meta->encoding);
    TEST_ASSERT_EQUAL_UINT8(0, meta->encrypted);
    TEST_ASSERT_EQUAL_UINT64(3, cmdx_reader_get_key_count(g_reader_lzo));

    tearDown_lzo();
}

static void test_lzo_lookup_alpha(void) {
    setUp_lzo();
    TEST_ASSERT_NOT_NULL(g_reader_lzo);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_lzo, "alpha", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);
    TEST_ASSERT_EQUAL_STRING("alpha", cmdx_key_entry_get_key(entries->items[0]));

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_lzo, "alpha", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_lzo);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_EQUAL_STRING("<i>alpha</i>", utf8);
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_lzo();
}

static void test_lzo_lookup_beta(void) {
    setUp_lzo();
    TEST_ASSERT_NOT_NULL(g_reader_lzo);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_lzo, "beta", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);
    TEST_ASSERT_EQUAL_STRING("beta", cmdx_key_entry_get_key(entries->items[0]));

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_lzo, "beta", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_lzo);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_EQUAL_STRING("Letter <b>beta</b>", utf8);
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_lzo();
}

static void test_lzo_lookup_gamma(void) {
    setUp_lzo();
    TEST_ASSERT_NOT_NULL(g_reader_lzo);

    cmdx_key_entry_list *entries =
        cmdx_get_key_entries_by_key(g_reader_lzo, "gamma", 1, false);
    TEST_ASSERT_NOT_NULL(entries);
    TEST_ASSERT_EQUAL_size_t(1, entries->count);
    TEST_ASSERT_EQUAL_STRING("gamma", cmdx_key_entry_get_key(entries->items[0]));

    cmdx_data_list *records =
        cmdx_get_content_records_by_key(g_reader_lzo, "gamma", 1, false);
    TEST_ASSERT_NOT_NULL(records);
    TEST_ASSERT_TRUE(records->count > 0);

    const cmdx_meta *meta = cmdx_reader_get_meta(g_reader_lzo);
    char *utf8 = content_to_utf8(records->items[0], meta);
    TEST_ASSERT_NOT_NULL(utf8);
    TEST_ASSERT_EQUAL_STRING("Capital version is \xce\x93 &lt;", utf8);
    free(utf8);

    cmdx_data_list_free(records);
    cmdx_key_entry_list_free(entries);
    tearDown_lzo();
}

// ============================================================
// Runner
// ============================================================

void run_dict_tests(void) {
    printf("--- Dictionary Tests: UTF-8 V2 ---\n");
    RUN_TEST(test_utf8_v2_meta);
    RUN_TEST(test_utf8_v2_lookup_Abc);
    RUN_TEST(test_utf8_v2_lookup_English);

    printf("--- Dictionary Tests: GBK V2 (encrypted) ---\n");
    RUN_TEST(test_gbk_v2_meta);
    RUN_TEST(test_gbk_v2_lookup_Abc);
    RUN_TEST(test_gbk_v2_lookup_chinese);
    RUN_TEST(test_gbk_v2_lookup_English);

    printf("--- Dictionary Tests: V3 ---\n");
    RUN_TEST(test_v3_meta);
    RUN_TEST(test_v3_lookup_chinese);
    RUN_TEST(test_v3_lookup_hangzhou);
    RUN_TEST(test_v3_lookup_zhichi);

    printf("--- Dictionary Tests: V3 (encrypted) ---\n");
    RUN_TEST(test_v3_enc_meta);
    RUN_TEST(test_v3_enc_lookup_anquan);
    RUN_TEST(test_v3_enc_lookup_meili);
    RUN_TEST(test_v3_enc_lookup_xiatian);

    printf("--- Dictionary Tests: LZO compression ---\n");
    RUN_TEST(test_lzo_meta);
    RUN_TEST(test_lzo_lookup_alpha);
    RUN_TEST(test_lzo_lookup_beta);
    RUN_TEST(test_lzo_lookup_gamma);
}
