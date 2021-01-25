#include "drbg.h"
#include "blake3.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <stdarg.h>

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
    abort();
}

// system entropy
#if defined(__APPLE__) || defined(HAVE_GETENTROPY)
#include <sys/random.h>
#include <unistd.h>

void drbg_entropy(void *buf, size_t bytes) {
    if (getentropy(buf, bytes) == -1) {
        die(true, "getentropy()");
    }
}

#elif defined(__linux__)
#include <sys/random.h>

void drbg_entropy(void *buf, size_t bytes) {
    if (getrandom(buf, bytes, 0) == -1) {
        die(true, "getrandom()");
    }
}

#elif defined(_WIN32)
#include <windows.h>

#define RtlGenRandom SystemFunction036

BOOLEAN NTAPI
RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#pragma comment(lib, "advapi32.lib")

inline void drbg_entropy(void *buf, size_t bytes) {
    RtlGenRandom((PVOID) buf, (ULONG) bytes);
}

#else
#error "TODO: add a system-specific entropy source"
#endif // system entropy

static _Thread_local struct {
    blake3_hasher st;
    uint64_t counter;
    bool initialized;
} drbg;

#define drbg_RESEED_INTERVAL (UINT64_C(1) << 48)

static void drbg_ratchet(void) {
    if (++drbg.counter == drbg_RESEED_INTERVAL) {
        drbg_reseed();
    } else {
        uint8_t key[BLAKE3_KEY_LEN];
        blake3_hasher_finalize(&drbg.st, key, BLAKE3_KEY_LEN);
        blake3_hasher_init_keyed(&drbg.st, key);
    }
}

static void drbg_ensure_init(void) {
    if (!drbg.initialized) {
        drbg.counter = 0;
        uint8_t seed[BLAKE3_KEY_LEN];
        drbg_entropy(seed, BLAKE3_KEY_LEN);
        drbg_ratchet();
        drbg.initialized = true;
    }
}

void drbg_randombytes(void *buf, unsigned long bytes) {
    drbg_ensure_init();
    uint8_t *b = (uint8_t *) buf;
    blake3_hasher_finalize_seek(&drbg.st, 64, b, bytes);
    drbg_ratchet();
}

void drbg_reseed(void) {
    drbg.initialized = false;
    drbg_ensure_init();
}
