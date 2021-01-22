#ifndef O1C_POLY1305_H
#define O1C_POLY1305_H

#include <stdint.h>
#include <stdalign.h>

#include "o1c_export.h"

#define o1c_poly1305_KEY_BYTES 32
#define o1c_poly1305_TAG_BYTES 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct o1c_poly1305_s {
    alignas(16) uint8_t state[96]; // large enough for 32-bit and 64-bit state representations
} o1c_poly1305_s, o1c_poly1305_t[1];

O1C_EXPORT void o1c_poly1305(uint8_t t[o1c_poly1305_TAG_BYTES], const uint8_t *m, unsigned long bytes,
                             const uint8_t k[o1c_poly1305_KEY_BYTES]);

O1C_EXPORT void o1c_poly1305_key_setup(o1c_poly1305_t ctx, const uint8_t k[o1c_poly1305_KEY_BYTES]);

O1C_EXPORT void o1c_poly1305_update(o1c_poly1305_t ctx, const uint8_t *m, unsigned long bytes);

O1C_EXPORT void o1c_poly1305_final(o1c_poly1305_t ctx, uint8_t t[o1c_poly1305_TAG_BYTES]);

void o1c_poly1305_blocks(o1c_poly1305_t ctx, const uint8_t *m, unsigned long bytes);

#ifdef __cplusplus
}
#endif

#endif //O1C_POLY1305_H
