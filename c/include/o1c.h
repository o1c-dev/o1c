#ifndef O1C_O1C_H
#define O1C_O1C_H

#include <stdbool.h>
#include <stdint.h>
#include <stdalign.h>

#include "o1c_export.h"
#include "blake3.h"

#ifdef __clang__
# if 100 * __clang_major__ + __clang_minor__ > 305
#  define O1C_UNROLL _Pragma("clang loop unroll(full)")
# endif
#endif

#ifndef O1C_UNROLL
# define O1C_UNROLL
#endif

#if defined _MSC_VER
# define O1C_NOINLINE __declspec(noinline)
#else

# include <unistd.h>

# define O1C_NOINLINE __attribute__((noinline))
#endif

#if !defined(__unix__) && (defined(__APPLE__) || defined(__linux__))
#define __unix__ 1
#endif

#include "drbg.h"
#include "util.h"
#include "chacha20.h"
#include "poly1305.h"
#include "xchacha20poly1305.h"

#ifdef __cplusplus
extern "C" {
#endif

#define o1c_hash_KEY_BYTES BLAKE3_KEY_LEN

typedef struct o1c_hash_s {
    alignas(16) uint8_t state[sizeof(blake3_hasher)];
} o1c_hash_s, o1c_hash_t[1];

O1C_EXPORT void o1c_hash_init(o1c_hash_t ctx);

O1C_EXPORT void o1c_hash_key_setup(o1c_hash_t ctx, const uint8_t k[o1c_hash_KEY_BYTES]);

O1C_EXPORT void o1c_hash_kdf_setup(o1c_hash_t ctx, const char *context);

O1C_EXPORT void o1c_hash_update(o1c_hash_t ctx, const uint8_t *m, unsigned long bytes);

O1C_EXPORT void o1c_hash_final(o1c_hash_t ctx, uint8_t *out, unsigned long out_bytes);

O1C_EXPORT void o1c_hash(uint8_t *out, unsigned long out_bytes, const uint8_t *in, unsigned long in_bytes);

#define o1c_scalar_BYTES 32
#define o1c_field_BYTES 32

typedef struct o1c_scalar_s {
    uint8_t v[o1c_scalar_BYTES];
} o1c_scalar_s, o1c_scalar_t[1];

O1C_EXPORT void o1c_scalar_random(o1c_scalar_t s);

// todo: migrate to struct
O1C_EXPORT void o1c_field_scalar_keypair(uint8_t pk[o1c_field_BYTES], uint8_t sk[o1c_scalar_BYTES]);

O1C_EXPORT void o1c_field_scalar_mul_base(uint8_t q[o1c_field_BYTES], const uint8_t n[o1c_scalar_BYTES]);

O1C_EXPORT bool
o1c_field_scalar_mul(uint8_t q[o1c_field_BYTES], const uint8_t n[o1c_scalar_BYTES], const uint8_t p[o1c_field_BYTES]);

#define o1c_po_group_element_BYTES 32
#define o1c_po_group_element_HASH_BYTES 64
typedef struct o1c_po_group_element_s {
    uint8_t v[o1c_po_group_element_BYTES];
} o1c_po_group_element_s, o1c_po_group_element_t[1];

O1C_EXPORT void o1c_po_group_keypair(o1c_po_group_element_t pk, o1c_scalar_t sk);

O1C_EXPORT bool o1c_po_group_scalar_mul(o1c_po_group_element_t q, const o1c_scalar_t n, const o1c_po_group_element_t p);

O1C_EXPORT bool o1c_po_group_scalar_mul_base(o1c_po_group_element_t q, const o1c_scalar_t n);

O1C_EXPORT void
o1c_po_group_element_from_hash(o1c_po_group_element_t q, const uint8_t h[o1c_po_group_element_HASH_BYTES]);

#define o1c_sign_BYTES 64
#define o1c_sign_KEY_BYTES 32
#define o1c_sign_KEYPAIR_BYTES 64

O1C_EXPORT void o1c_sign_seed_keypair(uint8_t pk[o1c_sign_KEY_BYTES], uint8_t sk[o1c_sign_KEYPAIR_BYTES],
                                      const uint8_t seed[o1c_sign_KEY_BYTES]);

O1C_EXPORT void o1c_sign_keypair(uint8_t pk[o1c_sign_KEY_BYTES], uint8_t sk[o1c_sign_KEYPAIR_BYTES]);

O1C_EXPORT void
o1c_sign_detached(uint8_t s[o1c_sign_BYTES], const uint8_t *m, unsigned long len,
                  const uint8_t sk[o1c_sign_KEYPAIR_BYTES]);

O1C_EXPORT bool
o1c_sign_verify_detached(const uint8_t s[o1c_sign_BYTES], const uint8_t *m, unsigned long len,
                         const uint8_t pk[o1c_sign_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif //O1C_O1C_H
