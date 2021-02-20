#pragma once

#include "o1c_export.h"
#include "curve25519.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define o1c_ristretto255_BYTES 32
#define o1c_ristretto255_KEY_BYTES 32
#define o1c_ristretto255_HASH_BYTES 64
#define o1c_ristretto255_SIGN_BYTES 64

typedef struct o1c_ristretto255_s {
    struct extended_point point;
} o1c_ristretto255_s, o1c_ristretto255_t[1];

O1C_EXPORT bool o1c_ristretto255_is_canonical(const uint8_t f[o1c_ristretto255_BYTES]);

O1C_EXPORT bool o1c_ristretto255_deserialize(o1c_ristretto255_t h, const uint8_t f[o1c_ristretto255_BYTES]);

O1C_EXPORT void o1c_ristretto255_serialize(uint8_t f[o1c_ristretto255_BYTES], const o1c_ristretto255_t p);

O1C_EXPORT void o1c_ristretto255_elligator(o1c_ristretto255_t h, const uint8_t f[o1c_ristretto255_BYTES]);

O1C_EXPORT bool o1c_ristretto255_equal(const o1c_ristretto255_t f, const o1c_ristretto255_t g);

O1C_EXPORT void o1c_ristretto255_from_hash(o1c_ristretto255_t q, const uint8_t h[o1c_ristretto255_HASH_BYTES]);

O1C_EXPORT bool o1c_ristretto255_scalar_mul(o1c_ristretto255_t q, const o1c_scalar25519_t n,
                                            const o1c_ristretto255_t p);

O1C_EXPORT bool o1c_ristretto255_scalar_mul_base(o1c_ristretto255_t q, const o1c_scalar25519_t n);

O1C_EXPORT void o1c_ristretto255b3_derive_pubkey(uint8_t pubkey[o1c_ristretto255_BYTES],
                                               const uint8_t key[o1c_ristretto255_KEY_BYTES]);

O1C_EXPORT void o1c_ristretto255b3_sign(uint8_t sig[o1c_ristretto255_SIGN_BYTES], const uint8_t *m, size_t m_len,
                                      const uint8_t key[o1c_ristretto255_KEY_BYTES]);

O1C_EXPORT bool o1c_ristretto255b3_verify(const uint8_t sig[o1c_ristretto255_SIGN_BYTES], const uint8_t *m, size_t m_len,
                                        const uint8_t pubkey[o1c_ristretto255_BYTES]);
