#include <unistd.h>
#include <sys/random.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

void drbg_entropy(void *buf, size_t bytes) {
    if (getentropy(buf, bytes) != 0) {
        fprintf(stderr, "getentropy() - %s", strerror(errno));
        abort();
    }
}
