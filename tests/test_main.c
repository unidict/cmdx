//
//  main.c
//  tests
//
//  Created by kejinlu on 2026/4/28.
//

#include "unity.h"
#include <stdio.h>

void run_reader_tests(void);
void run_meta_tests(void);
void run_lookup_tests(void);
void run_dict_tests(void);

int main(void) {
    printf("========================================\n");
    printf("  libcmdx Test Suite (Unity Framework)\n");
    printf("========================================\n\n");

    run_reader_tests();
    run_meta_tests();
    run_lookup_tests();
    run_dict_tests();

    printf("========================================\n");
    printf("  Test Summary\n");
    printf("========================================\n");
    return UnityEnd();
}
