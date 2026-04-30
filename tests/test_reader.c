//
//  test_reader.c
//  libcmdx tests
//

#include "unity.h"
#include "test_platform.h"
#include "cmdx_reader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_reader_open_valid(void) {
    const char *path = test_find_mdx_path();
    TEST_ASSERT_NOT_NULL_MESSAGE(path, "Test MDX file not found");

    cmdx_reader *reader = cmdx_reader_open(path, NULL);
    TEST_ASSERT_NOT_NULL(reader);
    cmdx_reader_close(reader);
}

static void test_reader_open_null_path(void) {
    cmdx_reader *reader = cmdx_reader_open(NULL, NULL);
    TEST_ASSERT_NULL(reader);
}

static void test_reader_open_nonexistent(void) {
    cmdx_reader *reader = cmdx_reader_open("/no/such/file.mdx", NULL);
    TEST_ASSERT_NULL(reader);
}

static void test_reader_open_invalid_file(void) {
    const char *tmp_path = "cmdx_test_invalid.mdx";
    FILE *fp = fopen(tmp_path, "wb");
    TEST_ASSERT_NOT_NULL(fp);
    const char *garbage = "this is not a valid mdx file";
    fwrite(garbage, 1, strlen(garbage), fp);
    fclose(fp);

    cmdx_reader *reader = cmdx_reader_open(tmp_path, NULL);
    TEST_ASSERT_NULL(reader);
    remove(tmp_path);
}

static void test_reader_close_null(void) {
    cmdx_reader_close(NULL);
}

static void test_reader_open_close_cycle(void) {
    const char *path = test_find_mdx_path();
    TEST_ASSERT_NOT_NULL(path);

    cmdx_reader *reader = cmdx_reader_open(path, NULL);
    TEST_ASSERT_NOT_NULL(reader);
    cmdx_reader_close(reader);

    reader = cmdx_reader_open(path, NULL);
    TEST_ASSERT_NOT_NULL(reader);
    cmdx_reader_close(reader);
}

void run_reader_tests(void) {
    printf("--- Reader Tests ---\n");
    RUN_TEST(test_reader_open_valid);
    RUN_TEST(test_reader_open_null_path);
    RUN_TEST(test_reader_open_nonexistent);
    RUN_TEST(test_reader_open_invalid_file);
    RUN_TEST(test_reader_close_null);
    RUN_TEST(test_reader_open_close_cycle);
}
