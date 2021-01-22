#ifndef O1C_ED25519_H
#define O1C_ED25519_H

#include <stdint.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>

#include "o1c_export.h"

#define o1c_ed25519_SEED_BYTES 32
#define o1c_ed25519_EXPANDED_BYTES 64
#define o1c_ed25519_PUBLIC_BYTES 32
#define o1c_ed25519_SIGN_BYTES 64

#ifdef __cplusplus
extern "C" {
#endif

typedef struct o1c_ed25519_seed_s {
    alignas(16) uint8_t v[o1c_ed25519_SEED_BYTES];
} o1c_ed25519_seed_s, o1c_ed25519_seed_t[1];

typedef struct o1c_ed25519_expanded_key_s {
    alignas(16) uint8_t v[o1c_ed25519_EXPANDED_BYTES];
} o1c_ed25519_expanded_key_s, o1c_ed25519_expanded_key_t[1];

typedef struct o1c_ed25519_public_key_s {
    alignas(16) uint8_t v[o1c_ed25519_PUBLIC_BYTES];
} o1c_ed25519_public_key_s, o1c_ed25519_public_key_t[1];

O1C_EXPORT void o1c_ed25519_expand_key(o1c_ed25519_expanded_key_t private_key, const o1c_ed25519_seed_t seed);

O1C_EXPORT void o1c_ed25519_keypair(o1c_ed25519_public_key_t public_key, o1c_ed25519_expanded_key_t private_key);

O1C_EXPORT void
o1c_ed25519_sign(uint8_t s[o1c_ed25519_SIGN_BYTES], const uint8_t *m, size_t len, const o1c_ed25519_expanded_key_t key);

O1C_EXPORT bool o1c_ed25519_verify(const uint8_t s[o1c_ed25519_SIGN_BYTES], const uint8_t *m, size_t len,
                                   const o1c_ed25519_public_key_t key);

#ifdef __cplusplus
}
#endif

#endif //O1C_ED25519_H
