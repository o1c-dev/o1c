// adapted from Daniel J. Bernstein's chacha20 public domain reference code

#include "o1c.h"
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

void o1c_crypto_key_setup(o1c_crypto_t ctx, const uint8_t key[o1c_crypto_KEY_BYTES]) {
    load32_le_n(ctx->state, chacha_sigma, 4);
    load32_le_n(ctx->state + 4, key, 8);
}

void o1c_crypto_nonce_setup(o1c_crypto_t ctx, const uint8_t nonce[o1c_crypto_NONCE_BYTES]) {
    ctx->state[12] = 0;
    load32_le_n(ctx->state + 13, nonce, 3);
}

void o1c_crypto_nonce_ic_setup(o1c_crypto_t ctx, const uint8_t nonce[o1c_crypto_NONCE_BYTES], uint32_t ic) {
    ctx->state[12] = ic;
    load32_le_n(ctx->state + 13, nonce, 3);
}

void o1c_crypto_bytes(o1c_crypto_t ctx, uint8_t *c, const uint8_t *m, size_t len) {
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
    uint8_t *ctarget;
    uint8_t tmp[64];
    size_t i;
    if (!len) return;

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
        if (len < 64) {
            for (i = 0;i < len;++i) tmp[i] = m[i];
            m = tmp;
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

        x0 = (x0) ^ (load32_le(m + 0));
        x1 = (x1) ^ (load32_le(m + 4));
        x2 = (x2) ^ (load32_le(m + 8));
        x3 = (x3) ^ (load32_le(m + 12));
        x4 = (x4) ^ (load32_le(m + 16));
        x5 = (x5) ^ (load32_le(m + 20));
        x6 = (x6) ^ (load32_le(m + 24));
        x7 = (x7) ^ (load32_le(m + 28));
        x8 = (x8) ^ (load32_le(m + 32));
        x9 = (x9) ^ (load32_le(m + 36));
        x10 = (x10) ^ (load32_le(m + 40));
        x11 = (x11) ^ (load32_le(m + 44));
        x12 = (x12) ^ (load32_le(m + 48));
        x13 = (x13) ^ (load32_le(m + 52));
        x14 = (x14) ^ (load32_le(m + 56));
        x15 = (x15) ^ (load32_le(m + 60));

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

        if (len <= 64) {
            if (len < 64) {
                for (i = 0;i < len;++i) ctarget[i] = c[i];
            }
            ctx->state[12] = j12;
            ctx->state[13] = j13;
            return;
        }
        len -= 64;
        c += 64;
        m += 64;
    }
}

void o1c_crypto_keystream(o1c_crypto_t ctx, uint8_t *s, size_t len) {
    o1c_bzero(s, len);
    o1c_crypto_bytes(ctx, s, s, len);
}

void o1c_crypto_stream(uint8_t *c, size_t len, const uint8_t n[o1c_crypto_NONCE_BYTES], const uint8_t k[o1c_crypto_KEY_BYTES]) {
    if (!len) return;
    o1c_crypto_t ctx;
    o1c_crypto_key_setup(ctx, k);
    o1c_crypto_nonce_setup(ctx, n);
    o1c_crypto_keystream(ctx, c, len);
    o1c_bzero(ctx, sizeof(o1c_crypto_s));
}

void o1c_crypto_xor_ic(uint8_t *out, const uint8_t *in, unsigned long bytes, const uint8_t n[o1c_crypto_NONCE_BYTES],
                       uint32_t ic, const uint8_t k[o1c_crypto_KEY_BYTES]) {
    if (!bytes) return;
    o1c_crypto_t ctx;
    o1c_crypto_key_setup(ctx, k);
    o1c_crypto_nonce_ic_setup(ctx, n, ic);
    o1c_crypto_bytes(ctx, out, in, bytes);
    o1c_bzero(ctx, sizeof(o1c_crypto_s));
}

void o1c_crypto_xor(uint8_t *out, const uint8_t *in, unsigned long bytes, const uint8_t n[o1c_crypto_NONCE_BYTES],
                    const uint8_t k[o1c_crypto_KEY_BYTES]) {
    o1c_crypto_xor_ic(out, in, bytes, n, 0, k);
}

