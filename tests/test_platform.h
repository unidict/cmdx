//
//  test_platform.h
//  libcmdx tests
//

#ifndef TEST_PLATFORM_H
#define TEST_PLATFORM_H

#include <stdio.h>
#include <string.h>

static const char *test_find_data_file(const char *filename) {
    static char found_path[1024] = {0};

    const char *last_sep = strrchr(__FILE__, '/');
    if (!last_sep) last_sep = strrchr(__FILE__, '\\');

    if (last_sep) {
        size_t dir_len = (size_t)(last_sep - __FILE__);
        snprintf(found_path, sizeof(found_path),
                 "%.*s/data/%s",
                 (int)dir_len, __FILE__, filename);
        FILE *fp = fopen(found_path, "rb");
        if (fp) {
            fclose(fp);
            return found_path;
        }
    }

    return NULL;
}

static const char *test_find_mdx_path(void) {
    return test_find_data_file("english-italian.mdx");
}

#endif /* TEST_PLATFORM_H */
