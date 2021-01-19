#ifndef O1C_SHA512_H
#define O1C_SHA512_H

#include <stdint.h>
#include <stddef.h>

#include "o1c.h"
#include "mem.h"

typedef struct sha512_ctx_s {
    uint64_t state[8];
    uint8_t block[128];
    uint64_t bytes_processed;
} sha512_ctx_t[1];

#define sha512_HASH_BYTES 64

void sha512_init(sha512_ctx_t ctx);

void sha512_update(sha512_ctx_t ctx, const uint8_t *msg, size_t len);

void sha512_final(sha512_ctx_t ctx, uint8_t *out);

static inline void
sha512(uint8_t *const out, const uint8_t *const msg, const size_t msg_len) {
    sha512_ctx_t ctx;
    sha512_init(ctx);
    sha512_update(ctx, msg, msg_len);
    sha512_final(ctx, out);
    o1c_bzero(ctx, sizeof ctx);
}

#endif //O1C_SHA512_H
