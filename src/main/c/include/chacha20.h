#pragma once

#include <stdint.h>

#include "o1c_export.h"

#define o1c_chacha20_KEY_BYTES 32
#define o1c_chacha20_NONCE_BYTES 12
#define o1c_hchacha20_KEY_BYTES 32
#define o1c_hchacha20_NONCE_BYTES 16

typedef struct o1c_chacha20_s {
    uint32_t state[16];
} o1c_chacha20_s, o1c_chacha20_t[1];

O1C_EXPORT void o1c_chacha20_key_setup(o1c_chacha20_t ctx, const uint8_t k[o1c_chacha20_KEY_BYTES]);

O1C_EXPORT void o1c_chacha20_nonce_setup(o1c_chacha20_t ctx, const uint8_t n[o1c_chacha20_NONCE_BYTES]);

O1C_EXPORT void o1c_chacha20_nonce_ic_setup(o1c_chacha20_t ctx, const uint8_t n[o1c_chacha20_NONCE_BYTES], uint32_t ic);

O1C_EXPORT void o1c_chacha20_bytes(o1c_chacha20_t ctx, uint8_t *c, const uint8_t *p, unsigned long bytes);

O1C_EXPORT void o1c_chacha20_keystream(o1c_chacha20_t ctx, uint8_t *s, unsigned long bytes);

O1C_EXPORT void o1c_chacha20_stream(uint8_t *c, unsigned long bytes, const uint8_t n[o1c_chacha20_NONCE_BYTES],
                                    const uint8_t k[o1c_chacha20_KEY_BYTES]);

O1C_EXPORT void
o1c_chacha20_xor_ic(uint8_t *out, const uint8_t *in, unsigned long bytes, const uint8_t n[o1c_chacha20_NONCE_BYTES],
                    uint32_t ic, const uint8_t k[o1c_chacha20_KEY_BYTES]);

O1C_EXPORT void
o1c_chacha20_xor(uint8_t *out, const uint8_t *in, unsigned long bytes, const uint8_t n[o1c_chacha20_NONCE_BYTES],
                 const uint8_t k[o1c_chacha20_KEY_BYTES]);

O1C_EXPORT void
o1c_hchacha20(uint8_t sk[o1c_hchacha20_KEY_BYTES], const uint8_t n[o1c_hchacha20_NONCE_BYTES],
              const uint8_t k[o1c_hchacha20_KEY_BYTES]);
