#include <stdint.h>
#include <stdbool.h>
#include <stdalign.h>

#include "o1c.h"
#include "mem.h"

// system entropy
#if defined(__APPLE__)
#include <sys/random.h>

inline void drbg_entropy(void *buf, size_t bytes) {
    getentropy(buf, bytes);
}

#elif defined(__linux__)
#include <sys/random.h>

inline void drbg_entropy(void *buf, size_t bytes) {
    getrandom(buf, bytes);
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
    alignas(16) struct o1c_crypto_s st;
    uint64_t counter;
    bool initialized;
} drbg_ctx;

static void drbg_ratchet() {
    uint8_t n[o1c_crypto_NONCE_BYTES] = {0};
    store64_le(n, drbg_ctx.counter++);
    o1c_crypto_nonce_setup(&drbg_ctx.st, n);
    o1c_crypto_keystream(&drbg_ctx.st, NULL, 0);
}

static void drbg_init() {
    drbg_entropy(&drbg_ctx.st, sizeof(struct o1c_crypto_s) + sizeof(uint64_t));
}

static void drbg_ensure_init() {
    if (!drbg_ctx.initialized) {
        drbg_init();
        o1c_crypto_keystream(&drbg_ctx.st, NULL, 0);
        drbg_ratchet();
        drbg_ctx.initialized = true;
    }
}

void drbg_randombytes(void *buf, unsigned long bytes) {
    drbg_ensure_init();
    uint8_t *b = (uint8_t *) buf;
    o1c_crypto_keystream(&drbg_ctx.st, b, bytes);
    drbg_ratchet();
}

void drbg_reseed(void) {
    drbg_ctx.initialized = false;
    drbg_ensure_init();
}
