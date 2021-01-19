#ifndef O1C_O1C_H
#define O1C_O1C_H

#include <stdbool.h>
#include <stdint.h>
#include <stdalign.h>

#include "o1c_export.h"

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

// Fills the provided buffer with random bytes.
O1C_EXPORT void drbg_randombytes(void *buf, unsigned long bytes);

// Reseeds the current DRBG.
O1C_EXPORT void drbg_reseed(void);

// Fills the provided buffer with system-provided external entropy.
void drbg_entropy(void *buf, unsigned long bytes);

O1C_EXPORT void o1c_bzero(void *buf, unsigned long bytes);

// Returns true in constant time if fst and snd have equal byte contents.
O1C_EXPORT bool o1c_mem_eq(const void *fst, const void *snd, unsigned long bytes);

// Returns true in constant time if a is all zeros.
O1C_EXPORT bool o1c_is_zero(const void *buf, unsigned long bytes);

// converts hex to binary and returns binary length or -1 on error
O1C_EXPORT long o1c_hex2bin(uint8_t *bin, unsigned long max_bin_len, const char *hex, unsigned long hex_len);

// Converts binary to hex and returns the hex string.
O1C_EXPORT char *o1c_bin2hex(char *hex, const uint8_t *bin, unsigned long bytes);

O1C_EXPORT unsigned long o1c_pad_len(unsigned long unpadded_len);

#define o1c_crypto_KEY_BYTES 32
#define o1c_crypto_NONCE_BYTES 12

typedef struct O1C_EXPORT o1c_crypto_s {
    uint32_t state[16];
} o1c_crypto_t[1];

O1C_EXPORT void o1c_crypto_key_setup(o1c_crypto_t ctx, const uint8_t k[o1c_crypto_KEY_BYTES]);

O1C_EXPORT void o1c_crypto_nonce_setup(o1c_crypto_t ctx, const uint8_t n[o1c_crypto_NONCE_BYTES]);

O1C_EXPORT void o1c_crypto_nonce_ic_setup(o1c_crypto_t ctx, const uint8_t n[o1c_crypto_NONCE_BYTES], uint32_t ic);

O1C_EXPORT void o1c_crypto_bytes(o1c_crypto_t ctx, uint8_t *c, const uint8_t *p, unsigned long bytes);

O1C_EXPORT void o1c_crypto_keystream(o1c_crypto_t ctx, uint8_t *s, unsigned long bytes);

O1C_EXPORT void o1c_crypto_stream(uint8_t *c, unsigned long bytes, const uint8_t n[o1c_crypto_NONCE_BYTES],
                                  const uint8_t k[o1c_crypto_KEY_BYTES]);

O1C_EXPORT void
o1c_crypto_xor_ic(uint8_t *out, const uint8_t *in, unsigned long bytes, const uint8_t n[o1c_crypto_NONCE_BYTES],
                  uint32_t ic, const uint8_t k[o1c_crypto_KEY_BYTES]);

O1C_EXPORT void
o1c_crypto_xor(uint8_t *out, const uint8_t *in, unsigned long bytes, const uint8_t n[o1c_crypto_NONCE_BYTES],
               const uint8_t k[o1c_crypto_KEY_BYTES]);

#define o1c_auth_KEY_BYTES 32
#define o1c_auth_TAG_BYTES 16

typedef struct O1C_EXPORT {
    alignas(16) uint8_t state[96]; // large enough for 32-bit and 64-bit state representations
} o1c_auth_t[1];

O1C_EXPORT void
o1c_auth(uint8_t t[o1c_auth_TAG_BYTES], const uint8_t *m, unsigned long bytes, const uint8_t k[o1c_auth_KEY_BYTES]);

O1C_EXPORT void o1c_auth_key_setup(o1c_auth_t ctx, const uint8_t k[o1c_auth_KEY_BYTES]);

O1C_EXPORT void o1c_auth_update(o1c_auth_t ctx, const uint8_t *m, unsigned long bytes);

O1C_EXPORT void o1c_auth_final(o1c_auth_t ctx, uint8_t t[o1c_auth_TAG_BYTES]);

#define o1c_aead_KEY_BYTES 32
#define o1c_aead_NONCE_BYTES 24
#define o1c_aead_TAG_BYTES 16

O1C_EXPORT void
o1c_aead_encrypt(uint8_t *c, uint8_t t[o1c_aead_TAG_BYTES], const uint8_t *m, unsigned long m_len, const uint8_t *ad,
                 unsigned long ad_len, const uint8_t n[o1c_aead_NONCE_BYTES], const uint8_t k[o1c_aead_KEY_BYTES]);

O1C_EXPORT bool
o1c_aead_decrypt(uint8_t *m, const uint8_t t[o1c_aead_TAG_BYTES], const uint8_t *c, unsigned long c_len,
                 const uint8_t *ad, unsigned long ad_len, const uint8_t n[o1c_aead_NONCE_BYTES],
                 const uint8_t k[o1c_aead_KEY_BYTES]);

#define o1c_scalar_BYTES 32
#define o1c_field_BYTES 32

O1C_EXPORT void o1c_field_scalar_keypair(uint8_t pk[o1c_field_BYTES], uint8_t sk[o1c_scalar_BYTES]);

O1C_EXPORT void o1c_field_scalar_mul_base(uint8_t q[o1c_field_BYTES], const uint8_t n[o1c_scalar_BYTES]);

O1C_EXPORT bool
o1c_field_scalar_mul(uint8_t q[o1c_field_BYTES], const uint8_t n[o1c_scalar_BYTES], const uint8_t p[o1c_field_BYTES]);

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

#endif //O1C_O1C_H
