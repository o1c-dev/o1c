#ifndef O1C_TEST_H
#define O1C_TEST_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

// Fills a buffer with the repeating sequence 0,1,2,...,255,0,1,...
static inline void init_buf(uint8_t *b, const size_t len) {
    for (size_t i = 0; i < len; ++i) b[i] = (uint8_t) (i % UINT8_MAX);
}

static inline noreturn void
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

#endif //O1C_TEST_H
