#pragma once

#include "o1c_export.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define o1c_scalar25519_BYTES 32
#define o1c_scalar25519_NONREDUCED_BYTES 64

typedef struct o1c_scalar25519_s {
    uint8_t v[o1c_scalar25519_BYTES];
} o1c_scalar25519_s, o1c_scalar25519_t[1];

O1C_EXPORT bool o1c_scalar25519_is_canonical(const o1c_scalar25519_t s);

O1C_EXPORT void o1c_scalar25519_random(o1c_scalar25519_t s);

O1C_EXPORT void o1c_scalar25519_reduce(o1c_scalar25519_t s, const uint8_t n[o1c_scalar25519_NONREDUCED_BYTES]);

O1C_EXPORT void o1c_scalar25519_deserialize(o1c_scalar25519_t s, const uint8_t n[o1c_scalar25519_BYTES]);

O1C_EXPORT void o1c_scalar25519_mul_add(o1c_scalar25519_t s, const o1c_scalar25519_t a, const o1c_scalar25519_t b,
                                        const o1c_scalar25519_t c);

O1C_EXPORT void o1c_scalar25519_negate(o1c_scalar25519_t neg, const o1c_scalar25519_t s);
