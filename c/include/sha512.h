#ifndef O1C_SHA512_H
#define O1C_SHA512_H

#include <stdint.h>
#include <stddef.h>

#include "o1c_export.h"

#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sha512_ctx_s {
    uint64_t state[8];
    uint8_t block[128];
    uint64_t bytes_processed;
} o1c_sha512_ctx_t[1];

#define o1c_sha512_HASH_BYTES 64

O1C_EXPORT void o1c_sha512_init(o1c_sha512_ctx_t ctx);

O1C_EXPORT void o1c_sha512_update(o1c_sha512_ctx_t ctx, const uint8_t *msg, size_t len);

O1C_EXPORT void o1c_sha512_final(o1c_sha512_ctx_t ctx, uint8_t *out);

O1C_EXPORT void o1c_sha512(uint8_t *out, const uint8_t *msg, size_t msg_len);

#ifdef __cplusplus
}
#endif

#endif //O1C_SHA512_H
