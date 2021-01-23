// adapted from Daniel J. Bernstein's chacha20 public domain reference code
#include "chacha20.h"
#include "util.h"
#include "mem.h"

#define U32V(v) ((uint32_t)(v) & UINT32_C(0xFFFFFFFF))

#define QUARTERROUND(a, b, c, d) \
  a = U32V((a)+(b)); d = rotl32((d)^(a),16); \
  c = U32V((c)+(d)); b = rotl32((b)^(c),12); \
  a = U32V((a)+(b)); d = rotl32((d)^(a), 8); \
  c = U32V((c)+(d)); b = rotl32((b)^(c), 7);

// sigma contains the ChaCha constants, which happen to be an ASCII string.
static const uint8_t chacha_sigma[16] = {'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
                                         '2', '-', 'b', 'y', 't', 'e', ' ', 'k'};

void o1c_chacha20_key_setup(o1c_chacha20_t ctx, const uint8_t k[o1c_chacha20_KEY_BYTES]) {
    load32_le_n(ctx->state, chacha_sigma, 4);
    load32_le_n(ctx->state + 4, k, 8);
}

void o1c_chacha20_nonce_setup(o1c_chacha20_t ctx, const uint8_t n[o1c_chacha20_NONCE_BYTES]) {
    ctx->state[12] = 0;
    load32_le_n(ctx->state + 13, n, 3);
}

void o1c_chacha20_nonce_ic_setup(o1c_chacha20_t ctx, const uint8_t n[o1c_chacha20_NONCE_BYTES], uint32_t ic) {
    ctx->state[12] = ic;
    load32_le_n(ctx->state + 13, n, 3);
}

void o1c_chacha20_bytes(o1c_chacha20_t ctx, uint8_t *c, const uint8_t *p, unsigned long bytes) {
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
    uint8_t *ctarget;
    uint8_t tmp[64];
    size_t i;
    if (!bytes) return;

    j0 = ctx->state[0];
    j1 = ctx->state[1];
    j2 = ctx->state[2];
    j3 = ctx->state[3];
    j4 = ctx->state[4];
    j5 = ctx->state[5];
    j6 = ctx->state[6];
    j7 = ctx->state[7];
    j8 = ctx->state[8];
    j9 = ctx->state[9];
    j10 = ctx->state[10];
    j11 = ctx->state[11];
    j12 = ctx->state[12];
    j13 = ctx->state[13];
    j14 = ctx->state[14];
    j15 = ctx->state[15];

    for (;;) {
        if (bytes < 64) {
            for (i = 0;i < bytes;++i) tmp[i] = p[i];
            p = tmp;
            ctarget = c;
            c = tmp;
        }
        x0 = j0;
        x1 = j1;
        x2 = j2;
        x3 = j3;
        x4 = j4;
        x5 = j5;
        x6 = j6;
        x7 = j7;
        x8 = j8;
        x9 = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;
        for (i = 20;i > 0;i -= 2) {
            QUARTERROUND( x0, x4, x8,x12)
            QUARTERROUND( x1, x5, x9,x13)
            QUARTERROUND( x2, x6,x10,x14)
            QUARTERROUND( x3, x7,x11,x15)
            QUARTERROUND( x0, x5,x10,x15)
            QUARTERROUND( x1, x6,x11,x12)
            QUARTERROUND( x2, x7, x8,x13)
            QUARTERROUND( x3, x4, x9,x14)
        }
        x0 = U32V(x0 + j0);
        x1 = U32V(x1 + j1);
        x2 = U32V(x2 + j2);
        x3 = U32V(x3 + j3);
        x4 = U32V(x4 + j4);
        x5 = U32V(x5 + j5);
        x6 = U32V(x6 + j6);
        x7 = U32V(x7 + j7);
        x8 = U32V(x8 + j8);
        x9 = U32V(x9 + j9);
        x10 = U32V(x10 + j10);
        x11 = U32V(x11 + j11);
        x12 = U32V(x12 + j12);
        x13 = U32V(x13 + j13);
        x14 = U32V(x14 + j14);
        x15 = U32V(x15 + j15);

        x0 = (x0) ^ (load32_le(p + 0));
        x1 = (x1) ^ (load32_le(p + 4));
        x2 = (x2) ^ (load32_le(p + 8));
        x3 = (x3) ^ (load32_le(p + 12));
        x4 = (x4) ^ (load32_le(p + 16));
        x5 = (x5) ^ (load32_le(p + 20));
        x6 = (x6) ^ (load32_le(p + 24));
        x7 = (x7) ^ (load32_le(p + 28));
        x8 = (x8) ^ (load32_le(p + 32));
        x9 = (x9) ^ (load32_le(p + 36));
        x10 = (x10) ^ (load32_le(p + 40));
        x11 = (x11) ^ (load32_le(p + 44));
        x12 = (x12) ^ (load32_le(p + 48));
        x13 = (x13) ^ (load32_le(p + 52));
        x14 = (x14) ^ (load32_le(p + 56));
        x15 = (x15) ^ (load32_le(p + 60));

        j12 = U32V(j12 + 1);
        if (!j12) {
            j12 = U32V(j13 + 1);
            /* stopping at 2^70 bytes per nonce is user's responsibility */
        }

        store32_le(c + 0,x0);
        store32_le(c + 4,x1);
        store32_le(c + 8,x2);
        store32_le(c + 12,x3);
        store32_le(c + 16,x4);
        store32_le(c + 20,x5);
        store32_le(c + 24,x6);
        store32_le(c + 28,x7);
        store32_le(c + 32,x8);
        store32_le(c + 36,x9);
        store32_le(c + 40,x10);
        store32_le(c + 44,x11);
        store32_le(c + 48,x12);
        store32_le(c + 52,x13);
        store32_le(c + 56,x14);
        store32_le(c + 60,x15);

        if (bytes <= 64) {
            if (bytes < 64) {
                memcpy(ctarget, c, bytes);
            }
            ctx->state[12] = j12;
            ctx->state[13] = j13;
            return;
        }
        bytes -= 64;
        c += 64;
        p += 64;
    }
}

void o1c_chacha20_keystream(o1c_chacha20_t ctx, uint8_t *s, unsigned long bytes) {
    o1c_bzero(s, bytes);
    o1c_chacha20_bytes(ctx, s, s, bytes);
}

void o1c_chacha20_stream(uint8_t *c, unsigned long bytes, const uint8_t n[o1c_chacha20_NONCE_BYTES],
                                    const uint8_t k[o1c_chacha20_KEY_BYTES]) {
    if (!bytes) return;
    o1c_chacha20_t ctx;
    o1c_chacha20_key_setup(ctx, k);
    o1c_chacha20_nonce_setup(ctx, n);
    o1c_chacha20_keystream(ctx, c, bytes);
    o1c_bzero(ctx, sizeof(o1c_chacha20_s));
}

void
o1c_chacha20_xor_ic(uint8_t *out, const uint8_t *in, unsigned long bytes, const uint8_t n[o1c_chacha20_NONCE_BYTES],
                    uint32_t ic, const uint8_t k[o1c_chacha20_KEY_BYTES]) {
    if (!bytes) return;
    o1c_chacha20_t ctx;
    o1c_chacha20_key_setup(ctx, k);
    o1c_chacha20_nonce_ic_setup(ctx, n, ic);
    o1c_chacha20_bytes(ctx, out, in, bytes);
    o1c_bzero(ctx, sizeof(o1c_chacha20_s));
}

void
o1c_chacha20_xor(uint8_t *out, const uint8_t *in, unsigned long bytes, const uint8_t n[o1c_chacha20_NONCE_BYTES],
                 const uint8_t k[o1c_chacha20_KEY_BYTES]) {
    o1c_chacha20_xor_ic(out, in, bytes, n, 0, k);
}

void
o1c_hchacha20(uint8_t sk[o1c_hchacha20_KEY_BYTES], const uint8_t n[o1c_hchacha20_NONCE_BYTES],
              const uint8_t k[o1c_hchacha20_KEY_BYTES]) {
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    x0 = 0x61707865;
    x1 = 0x3320646e;
    x2 = 0x79622d32;
    x3 = 0x6b206574;
    x4  = load32_le(k +  0);
    x5  = load32_le(k +  4);
    x6  = load32_le(k +  8);
    x7  = load32_le(k + 12);
    x8  = load32_le(k + 16);
    x9  = load32_le(k + 20);
    x10 = load32_le(k + 24);
    x11 = load32_le(k + 28);
    x12 = load32_le(n +  0);
    x13 = load32_le(n +  4);
    x14 = load32_le(n +  8);
    x15 = load32_le(n + 12);

    for (int i = 0; i < 10; i++) {
        QUARTERROUND(x0, x4,  x8, x12);
        QUARTERROUND(x1, x5,  x9, x13);
        QUARTERROUND(x2, x6, x10, x14);
        QUARTERROUND(x3, x7, x11, x15);
        QUARTERROUND(x0, x5, x10, x15);
        QUARTERROUND(x1, x6, x11, x12);
        QUARTERROUND(x2, x7,  x8, x13);
        QUARTERROUND(x3, x4,  x9, x14);
    }

    store32_le(sk +  0, x0);
    store32_le(sk +  4, x1);
    store32_le(sk +  8, x2);
    store32_le(sk + 12, x3);
    store32_le(sk + 16, x12);
    store32_le(sk + 20, x13);
    store32_le(sk + 24, x14);
    store32_le(sk + 28, x15);
}
