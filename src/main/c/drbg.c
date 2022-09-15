#include "drbg.h"
#include "blake3.h"

#include <stdint.h>
#include <stdbool.h>

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
        blake3_hasher_init_keyed(&drbg.st, seed);
        drbg_ratchet();
        drbg.initialized = true;
    }
}

void drbg_randombytes(void *buf, unsigned long bytes) {
    drbg_ensure_init();
    blake3_hasher_finalize_seek(&drbg.st, 64, (uint8_t *) buf, bytes);
    drbg_ratchet();
}

void drbg_reseed(void) {
    drbg.initialized = false;
    drbg_ensure_init();
}
