#include <sys/random.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

void drbg_entropy(void *buf, size_t bytes) {
    if (getrandom(buf, bytes, 0) == -1) {
        fprintf(stderr, "getrandom() - %s", strerror(errno));
        abort();
    }
}
