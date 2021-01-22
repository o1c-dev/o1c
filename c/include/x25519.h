#ifndef O1C_X25519_H
#define O1C_X25519_H

#include <stdint.h>
#include <stdalign.h>
#include <stdbool.h>

#include "o1c_export.h"

#define o1c_x25519_SCALAR_BYTES 32
#define o1c_x25519_ELEMENT_BYTES 32

#ifdef __cplusplus
extern "C" {
#endif

typedef struct o1c_x25519_scalar_s {
    alignas(16) uint8_t v[o1c_x25519_SCALAR_BYTES];
} o1c_x25519_scalar_s, o1c_x25519_scalar_t[1];

typedef struct o1c_x25519_element_s {
    alignas(16) uint8_t v[o1c_x25519_ELEMENT_BYTES];
} o1c_x25519_element_s, o1c_x25519_element_t[1];

O1C_EXPORT void o1c_x25519_scalar_random(o1c_x25519_scalar_t s);

O1C_EXPORT void o1c_x25519_keypair(o1c_x25519_element_t pk, o1c_x25519_scalar_t sk);

O1C_EXPORT bool
o1c_x25519_scalar_mul(o1c_x25519_element_t q, const o1c_x25519_scalar_t n, const o1c_x25519_element_t p);

O1C_EXPORT void o1c_x25519_scalar_mul_base(o1c_x25519_element_t q, const o1c_x25519_scalar_t n);

#ifdef __cplusplus
}
#endif

#endif //O1C_X25519_H
