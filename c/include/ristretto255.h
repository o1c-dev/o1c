#pragma once

#include "o1c_export.h"
#include "hash.h"

#include <stdint.h>
#include <stdalign.h>
#include <stdbool.h>

#define o1c_ristretto255_SCALAR_BYTES 32
#define o1c_ristretto255_ELEMENT_BYTES 32
#define o1c_ristretto255_HASH_BYTES 64
#define o1c_ristretto255_SIGN_BYTES 64

typedef struct o1c_ristretto255_scalar_s {
    alignas(16) uint8_t v[o1c_ristretto255_SCALAR_BYTES];
} o1c_ristretto255_scalar_s, o1c_ristretto255_scalar_t[1];

typedef struct o1c_ristretto255_element_s {
    alignas(16) uint8_t v[o1c_ristretto255_ELEMENT_BYTES];
} o1c_ristretto255_element_s, o1c_ristretto255_element_t[1];

O1C_EXPORT void o1c_ristretto255_scalar_random(o1c_ristretto255_scalar_t s);

O1C_EXPORT void o1c_ristretto255_keypair(o1c_ristretto255_element_t pk, o1c_ristretto255_scalar_t sk);

O1C_EXPORT void o1c_ristretto255_from_hash(o1c_ristretto255_element_t q, const uint8_t h[o1c_ristretto255_HASH_BYTES]);

O1C_EXPORT bool o1c_ristretto255_scalar_mul(o1c_ristretto255_element_t q, const o1c_ristretto255_scalar_t n,
                                            const o1c_ristretto255_element_t p);

O1C_EXPORT bool o1c_ristretto255_scalar_mul_base(o1c_ristretto255_element_t q, const o1c_ristretto255_scalar_t n);

#ifdef TODO_SIGNCRYPT
typedef struct o1c_ristretto255_aead_s {
    size_t key_bytes;

    void (*encrypt)(uint8_t *c, uint8_t *t, const uint8_t *m, size_t m_len, const uint8_t *ad, size_t ad_len,
                    const uint8_t *n, const uint8_t *k);

    bool (*decrypt)(uint8_t *m, const uint8_t *t, const uint8_t *c, size_t c_len, const uint8_t *ad, size_t ad_len,
                    const uint8_t *n, const uint8_t *k);
} o1c_ristretto255_aead_s, o1c_ristretto255_aead_t[1];

O1C_EXPORT bool
o1c_ristretto255_signcrypt(const o1c_ristretto255_aead_t aead, uint8_t sig[o1c_ristretto255_SIGN_BYTES], uint8_t *tag,
                           uint8_t *c, const uint8_t *m, size_t m_len, const uint8_t *ad, size_t ad_len,
                           const uint8_t *nonce,
                           const uint8_t *sender_id, size_t sender_id_len,
                           const uint8_t *recipient_id, size_t recipient_id_len,
                           const uint8_t *context, size_t context_len,
                           const o1c_ristretto255_scalar_t sender_sk,
                           const o1c_ristretto255_element_t recipient_pk);

O1C_EXPORT bool
o1c_ristretto255_signcrypt_open(const o1c_ristretto255_aead_t aead,
                                const uint8_t sig[o1c_ristretto255_SIGN_BYTES], const uint8_t *tag,
                                uint8_t *m, const uint8_t *c, size_t c_len, const uint8_t *ad, size_t ad_len,
                                const uint8_t *nonce,
                                const uint8_t *sender_id, size_t sender_id_len,
                                const uint8_t *recipient_id, size_t recipient_id_len,
                                const uint8_t *context, size_t context_len,
                                const o1c_ristretto255_element_t sender_pk,
                                const o1c_ristretto255_scalar_t recipient_sk);
#endif
