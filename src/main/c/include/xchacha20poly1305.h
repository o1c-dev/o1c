#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "o1c_export.h"

#define o1c_xchacha20poly1305_KEY_BYTES 32
#define o1c_xchacha20poly1305_NONCE_BYTES 24
#define o1c_xchacha20poly1305_TAG_BYTES 16

O1C_EXPORT void
o1c_xchacha20poly1305_encrypt(uint8_t *c, uint8_t t[o1c_xchacha20poly1305_TAG_BYTES], const uint8_t *m,
                              size_t m_len, const uint8_t *ad, size_t ad_len,
                              const uint8_t n[o1c_xchacha20poly1305_NONCE_BYTES],
                              const uint8_t k[o1c_xchacha20poly1305_KEY_BYTES]);

O1C_EXPORT bool
o1c_xchacha20poly1305_decrypt(uint8_t *m, const uint8_t t[o1c_xchacha20poly1305_TAG_BYTES], const uint8_t *c,
                              size_t c_len, const uint8_t *ad, size_t ad_len,
                              const uint8_t n[o1c_xchacha20poly1305_NONCE_BYTES],
                              const uint8_t k[o1c_xchacha20poly1305_KEY_BYTES]);
