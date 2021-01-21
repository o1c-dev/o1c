#ifndef O1C_TEST_UTIL_H
#define O1C_TEST_UTIL_H

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdnoreturn.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#include "o1c.h"
#include "mem.h"

static noreturn void
die(bool print_errno, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    if (print_errno) {
        fprintf(stderr, "- %s", strerror(errno));
    }
    fprintf(stderr, "\n");
    exit(1);
}

static void assert_eq(const uint8_t *expected, const uint8_t *actual, const size_t len) {
    if (!o1c_mem_eq(expected, actual, len)) {
        const size_t hex_len = len * 2 + 1;
        char hex_expected[hex_len];
        char hex_actual[hex_len];
        die(false, "Expected: %s\nActual:   %s\n", o1c_bin2hex(hex_expected, expected, len),
            o1c_bin2hex(hex_actual, actual, len));
    }
}

#endif //O1C_TEST_UTIL_H
