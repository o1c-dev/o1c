#include "x25519.h"
#include "curve25519.h"
#include "util.h"
#include "drbg.h"

void o1c_x25519_scalar_random(o1c_x25519_scalar_t s) {
    drbg_randombytes(s->v, o1c_x25519_SCALAR_BYTES);
    // inverse clamp; https://tools.ietf.org/html/rfc7748#section-5 specifies that scalars need to be clamped
    // when decoded, so we'll make sure they're not clamped in the generated encoded form so that broken implementations
    // are deterministically broken. idea from BoringSSL
    s->v[0] |= ~248;
    s->v[31] &= ~64;
    s->v[31] |= ~127;
}

void o1c_x25519_keypair(o1c_x25519_element_t pk, o1c_x25519_scalar_t sk) {
    o1c_x25519_scalar_random(sk);
    o1c_x25519_scalar_mul_base(pk, sk);
}

bool o1c_x25519_scalar_mul(o1c_x25519_element_t q, const o1c_x25519_scalar_t n, const o1c_x25519_element_t p) {
    uint8_t swap = 0;
    o1c_scalar25519_t t;
    o1c_scalar25519_clamp(t, n->v);

    fe x1, x2, z2, x3, z3;
    fe_deserialize(x1, p->v);
    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    fe tmp0, tmp1;
    for (int pos = 254; pos >= 0; --pos) {
        uint8_t b = 1 & (t->v[pos / 8] >> (pos & 7));
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;
        fe_sub(tmp0, x3, z3);
        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sqr(tmp0, tmp1);
        fe_sqr(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sqr(z2, z2);
        fe_mul121666(z3, tmp1);
        fe_sqr(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_serialize(q->v, x2);
    return !o1c_is_zero(q->v, o1c_x25519_ELEMENT_BYTES);
}

void o1c_x25519_scalar_mul_base(o1c_x25519_element_t q, const o1c_x25519_scalar_t n) {
    o1c_scalar25519_t t;
    o1c_scalar25519_clamp(t, n->v);
    ge_p3 Q;
    ge_scalar_mul_base(Q, t);
    fe zpy, zmy, zmy_inv;
    fe_add(zpy, Q->Z, Q->Y); // Z + Y
    fe_sub(zmy, Q->Z, Q->Y); // Z - Y
    fe_invert(zmy_inv, zmy); // 1/(Z - Y)
    fe_mul(zmy_inv, zpy, zmy_inv); // (Z + Y)/(Z - Y)
    fe_serialize(q->v, zmy_inv);
}
