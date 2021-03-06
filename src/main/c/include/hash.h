#pragma once

#include "o1c_export.h"
#include "blake3.h"

#include <stdint.h>
#include <stdalign.h>

#define o1c_hash_KEY_BYTES BLAKE3_KEY_LEN
#define o1c_hash_STATE_BYTES sizeof(blake3_hasher)

typedef struct o1c_hash_s {
    alignas(16) uint8_t state[o1c_hash_STATE_BYTES];
} o1c_hash_s, o1c_hash_t[1];

O1C_EXPORT void o1c_hash_init(o1c_hash_t ctx);

O1C_EXPORT void o1c_hash_key_setup(o1c_hash_t ctx, const uint8_t k[o1c_hash_KEY_BYTES]);

O1C_EXPORT void o1c_hash_kdf_setup(o1c_hash_t ctx, const char *context);

O1C_EXPORT void o1c_hash_update(o1c_hash_t ctx, const uint8_t *m, size_t bytes);

O1C_EXPORT void o1c_hash_final(o1c_hash_t ctx, uint8_t *out, size_t out_bytes);

O1C_EXPORT void o1c_hash(uint8_t *out, size_t out_bytes, const uint8_t *in, size_t in_bytes);
