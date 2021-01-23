// adapted from poly1305-donna; public domain or MIT license
#include <assert.h>

static_assert(ARCH_WORD_BITS == 32 || ARCH_WORD_BITS == 64, "Unsupported architecture");

#include "poly1305.h"
#include "util.h"

#if (ARCH_WORD_BITS == 32)
#define RH_LIMBS 5
#define PAD_LIMBS 4
typedef unsigned long limb_t;
#else
#define RH_LIMBS 3
#define PAD_LIMBS 2
typedef unsigned long long limb_t;
#endif

#define poly1305_BLOCK_SIZE 16

typedef struct poly1305_state_internal_s {
    limb_t r[RH_LIMBS];
    limb_t h[RH_LIMBS];
    limb_t pad[PAD_LIMBS];
    unsigned long leftover;
    unsigned char buffer[poly1305_BLOCK_SIZE];
    unsigned char final;
} poly1305_state_internal_s, poly1305_state_internal_t[1];

#if (ARCH_WORD_BITS == 64)

#include "poly1305_64.c"

#else

#include "poly1305_32.c"

#endif

void o1c_poly1305(uint8_t t[o1c_poly1305_TAG_BYTES], const uint8_t *m, unsigned long bytes,
                  const uint8_t k[o1c_poly1305_KEY_BYTES]) {
    o1c_poly1305_t ctx;
    o1c_poly1305_key_setup(ctx, k);
    o1c_poly1305_update(ctx, m, bytes);
    o1c_poly1305_final(ctx, t);
    o1c_bzero(ctx, sizeof(o1c_poly1305_s));
}

void o1c_poly1305_update(o1c_poly1305_t ctx, const uint8_t *m, unsigned long bytes) {
    poly1305_state_internal_s *st = (poly1305_state_internal_s *) ctx->state;
    unsigned long i;

    /* handle leftover */
    if (st->leftover) {
        unsigned long want = (poly1305_BLOCK_SIZE - st->leftover);
        if (want > bytes)
            want = bytes;
        for (i = 0; i < want; i++)
            st->buffer[st->leftover + i] = m[i];
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < poly1305_BLOCK_SIZE)
            return;
        o1c_poly1305_blocks(ctx, st->buffer, poly1305_BLOCK_SIZE);
        st->leftover = 0;
    }

    /* process full blocks */
    if (bytes >= poly1305_BLOCK_SIZE) {
        unsigned long want = (bytes & ~(poly1305_BLOCK_SIZE - 1));
        o1c_poly1305_blocks(ctx, m, want);
        m += want;
        bytes -= want;
    }

    /* store leftover */
    if (bytes) {
        for (i = 0; i < bytes; i++)
            st->buffer[st->leftover + i] = m[i];
        st->leftover += bytes;
    }
}
