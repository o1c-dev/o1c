#include "drbg.h"
#include "chacha20.h"

#include "mem.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdalign.h>
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
    alignas(16) o1c_chacha20_s st;
    uint64_t counter;
    bool initialized;
} drbg_ctx;

#define drbg_RESEED_INTERVAL (UINT64_C(1) << 48)

static void drbg_ratchet(void) {
    uint8_t n[o1c_chacha20_NONCE_BYTES] = {0};
    store64_le(n, drbg_ctx.counter++);
    o1c_chacha20_nonce_setup(&drbg_ctx.st, n);
    o1c_chacha20_keystream(&drbg_ctx.st, NULL, 0);
}

static void drbg_init(void) {
    drbg_entropy(&drbg_ctx.st, sizeof(o1c_chacha20_s));
    drbg_ctx.counter = 0;
}

static void drbg_ensure_init(void) {
    if (!drbg_ctx.initialized) {
        drbg_init();
        o1c_chacha20_keystream(&drbg_ctx.st, NULL, 0);
        drbg_ratchet();
        drbg_ctx.initialized = true;
    } else if (drbg_ctx.counter > drbg_RESEED_INTERVAL) {
        drbg_reseed();
    }
}

void drbg_randombytes(void *buf, unsigned long bytes) {
    drbg_ensure_init();
    uint8_t *b = (uint8_t *) buf;
    o1c_chacha20_keystream(&drbg_ctx.st, b, bytes);
    drbg_ratchet();
}

void drbg_reseed(void) {
    drbg_ctx.initialized = false;
    drbg_ensure_init();
}
