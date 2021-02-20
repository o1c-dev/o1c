#include "ristretto255.h"
#include "curve25519.h"
#include "util.h"
#include "hash.h"

// TODO: separate constants
#include "curve25519/curve25519_tables.h"

#include <string.h>

bool o1c_ristretto255_is_canonical(const uint8_t f[o1c_ristretto255_BYTES]) {
    uint8_t C, D, E;
    unsigned int i;
    C = (f[31] & 0x7f) ^ 0x7f;
    for (i = 30; i > 0; i--) {
        C |= f[i] ^ 0xff;
    }
    C = (((unsigned int) C) - 1U) >> 8;
    D = (0xed - 1U - (unsigned int) f[0]) >> 8;
    E = f[31] >> 7;

    return 1 - (((C & D) | E | f[0]) & 1);
}

// https://ristretto.group/formulas/invsqrt.html
static bool sqrt_ratio_i(fe x, const fe u, const fe v) {
    fe v3, vxx, m_root_check, p_root_check, f_root_check, x_sqrt_m1;
    bool correct_sign_sqrt, flipped_sign_sqrt, flipped_sign_sqrt_i;
    fe_sqr(v3, v);
    fe_mul(v3, v3, v); // v3 = v^3
    fe_sqr(x, v3);
    fe_mul(x, x, v);
    fe_mul(x, x, u); // x = uv^7
    fe_pow22523(x, x);
    fe_mul(x, x, v3);
    fe_mul(x, x, u); // x = uv^3(uv^7)^((q-5)/8)

    fe_sqr(vxx, x);
    fe_mul(vxx, vxx, v);
    fe_sub(m_root_check, vxx, u);
    correct_sign_sqrt = !fe_is_nonzero(m_root_check);

    fe_add(p_root_check, vxx, u);
    flipped_sign_sqrt = !fe_is_nonzero(p_root_check);

    fe_mul(f_root_check, u, sqrtm1);
    fe_add(f_root_check, vxx, f_root_check);
    flipped_sign_sqrt_i = !fe_is_nonzero(f_root_check);

    fe_mul(x_sqrt_m1, x, sqrtm1);
    fe_select(x, flipped_sign_sqrt | flipped_sign_sqrt_i, x, x_sqrt_m1);
    fe_abs(x, x);
    return correct_sign_sqrt | flipped_sign_sqrt;
}

// https://ristretto.group/formulas/decoding.html
bool o1c_ristretto255_deserialize(o1c_ristretto255_t h, const uint8_t f[o1c_ristretto255_BYTES]) {
    fe inv_sqrt, one, s, ss, u1, u2, u1u1, u2u2, v, v_u2u2;
    if (!o1c_ristretto255_is_canonical(f)) return false;

    fe_deserialize(s, f);
    fe_sqr(ss, s); // s^2
    fe_1(u1);
    fe_sub(u1, u1, ss); // (1-s^2)
    fe_sqr(u1u1, u1); // (1-s^2)^2
    fe_1(u2);
    fe_add(u2, u2, ss); // (1+s^2)
    fe_sqr(u2u2, u2); // (1+s^2)^2
    fe_mul(v, d, u1u1);
    fe_neg(v, v);
    fe_sub(v, v, u2u2); // -(d*u1^2)-u2^2
    fe_mul(v_u2u2, v, u2u2); // v*u2^2

    fe_1(one);
    bool ratio_is_square = sqrt_ratio_i(inv_sqrt, one, v_u2u2);
    fe_mul(h->point.X, inv_sqrt, u2);

    fe_mul(h->point.Y, inv_sqrt, h->point.X);
    fe_mul(h->point.Y, h->point.Y, v);
    fe_mul(h->point.Y, h->point.Y, u1);

    fe_mul(h->point.X, h->point.X, s);
    fe_add(h->point.X, h->point.X, h->point.X);
    fe_abs(h->point.X, h->point.X);
    fe_mul(h->point.T, h->point.X, h->point.Y);
    fe_1(h->point.Z);
    return ((1 - ratio_is_square) | fe_is_neg(h->point.T) | !fe_is_nonzero(h->point.Y)) == 0;
}

// https://ristretto.group/formulas/encoding.html
void o1c_ristretto255_serialize(uint8_t f[o1c_ristretto255_BYTES], const o1c_ristretto255_t p) {
    fe u1;
    fe_add(u1, p->point.Z, p->point.Y); // Z+Y
    fe zmy;
    fe_sub(zmy, p->point.Z, p->point.Y); // Z-Y
    fe_mul(u1, u1, zmy); // (Z+Y)*(Z-Y)
    fe u2;
    fe_mul(u2, p->point.X, p->point.Y); // X*Y
    fe u1_u2u2;
    fe_sqr(u1_u2u2, u2);
    fe_mul(u1_u2u2, u1_u2u2, u1); // u1*u2^2
    fe inv_sqrt, one;
    fe_1(one);
    (void) sqrt_ratio_i(inv_sqrt, one, u1_u2u2);
    fe den1;
    fe_mul(den1, inv_sqrt, u1);
    fe den2;
    fe_mul(den2, inv_sqrt, u2);
    fe z_inv;
    fe_mul(z_inv, den1, den2);
    fe_mul(z_inv, z_inv, p->point.T); // den1*den2*T
    fe ix;
    fe_mul(ix, p->point.X, sqrtm1); // X*sqrt(-1)
    fe iy;
    fe_mul(iy, p->point.Y, sqrtm1); // Y*sqrt(-1)
    fe eden;
    fe_mul(eden, den1, invsqrtamd); // den1/sqrt(a-d)
    fe t_z_inv;
    fe_mul(t_z_inv, p->point.T, z_inv); // T*z_inv

    bool rotate = fe_is_neg(t_z_inv);
    fe x, y, den_inv;
    fe_select(x, rotate, p->point.X, iy);
    fe_select(y, rotate, p->point.Y, ix);
    fe_select(den_inv, rotate, den2, eden);

    fe x_z_inv;
    fe_mul(x_z_inv, x, z_inv);
    fe y_neg;
    fe_neg(y_neg, y);
    fe_cmov(y, y_neg, fe_is_neg(x_z_inv));

    fe_sub(zmy, p->point.Z, y);
    fe_mul(zmy, zmy, den_inv);
    fe_abs(zmy, zmy);
    fe_reduce(zmy, zmy);
    fe_serialize(f, zmy);
}

// https://ristretto.group/formulas/elligator.html
// https://ristretto.group/details/elligator_in_extended.html
void o1c_ristretto255_elligator(o1c_ristretto255_t h, const uint8_t f[o1c_ristretto255_BYTES]) {
    fe t;
    fe_deserialize(t, f);
    fe r;
    fe_sqr(r, t);
    fe_mul(r, r, sqrtm1); // sqrt(-1)*t^2
    fe u, one;
    fe_1(one);
    fe_add(u, r, one);
    fe_mul(u, u, onemsqd); // (r+1)*(1-d^2)
    fe c;
    fe_neg(c, one); // -1
    fe v, rd;
    fe_mul(rd, r, d);
    fe_sub(v, c, rd);
    fe rpd;
    fe_add(rpd, r, d);
    fe_mul(v, v, rpd); // (c-r*d)*(r+d)
    fe s;
    bool wasnt_square = !sqrt_ratio_i(s, u, v);
    fe s_prime;
    fe_mul(s_prime, s, t);
    fe_abs(s_prime, s_prime);
    fe_neg(s_prime, s_prime); // -|s*t|
    fe_cmov(s, s_prime, wasnt_square);
    fe_cmov(c, r, wasnt_square);

    fe n;
    fe_sub(n, r, one);
    fe_mul(n, n, c);
    fe_mul(n, n, sqdmone);
    fe_sub(n, n, v); // c*(r-1)*(d-1)^2-v
    fe w0;
    fe_add(w0, s, s);
    fe_mul(w0, w0, v); // 2s*v
    fe w1;
    fe_mul(w1, n, sqrtadm1); // n*sqrt(ad-1)
    fe ss;
    fe_sqr(ss, s); // s^2
    fe w2;
    fe_sub(w2, one, ss); // 1-s^2
    fe w3;
    fe_add(w3, one, ss); // 1+s^2

    fe_mul(h->point.X, w0, w3);
    fe_mul(h->point.Y, w2, w1);
    fe_mul(h->point.Z, w1, w3);
    fe_mul(h->point.T, w0, w2);
}

bool o1c_ristretto255_equal(const o1c_ristretto255_t f, const o1c_ristretto255_t g) {
    fe x1y2, y1x2, y1y2, x1x2;
    fe_mul(x1y2, f->point.X, g->point.Y);
    fe_mul(y1x2, f->point.Y, g->point.X);
    fe_mul(y1y2, f->point.Y, g->point.Y);
    fe_mul(x1x2, f->point.X, g->point.X);
    return o1c_mem_eq(x1y2, y1x2, sizeof(fe)) | o1c_mem_eq(y1y2, x1x2, sizeof(fe));
}

void o1c_ristretto255_from_hash(o1c_ristretto255_t q, const uint8_t h[o1c_ristretto255_HASH_BYTES]) {
    o1c_ristretto255_t p0, p1;
    o1c_ristretto255_elligator(p0, h);
    o1c_ristretto255_elligator(p1, h + o1c_ristretto255_BYTES);
    ge_cached p1_cached;
    ge_ext_to_proj_niels(p1_cached, &p1->point);
    ge_p1p1 p1_p1p1;
    ge_ext_add(p1_p1p1, &p0->point, p1_cached);
    ge_comp_to_ext(&q->point, p1_p1p1);
}

bool o1c_ristretto255_scalar_mul(o1c_ristretto255_t q, const o1c_scalar25519_t n, const o1c_ristretto255_t p) {
    ge_scalar_mul(&q->point, n, &p->point);
    uint8_t result[o1c_ristretto255_BYTES];
    o1c_ristretto255_serialize(result, q);
    return !o1c_is_zero(result, o1c_ristretto255_BYTES);
}

bool o1c_ristretto255_scalar_mul_base(o1c_ristretto255_t q, const o1c_scalar25519_t n) {
    ge_scalar_mul_base(&q->point, n);
    uint8_t result[o1c_ristretto255_BYTES];
    o1c_ristretto255_serialize(result, q);
    return !o1c_is_zero(result, o1c_ristretto255_BYTES);
}

void o1c_ristretto255b3_derive_pubkey(uint8_t *const pubkey, const uint8_t *const key) {
    o1c_hash_t st;
    // Ed25519 uses SHA-512 as an AMAC here to derive the scalar and prefix
    // this uses Blake3 in keyed mode to derive the same
    o1c_hash_key_setup(st, key);
    uint8_t scalar[o1c_scalar25519_BYTES];
    // we don't need to compute the prefix quite yet, so we'll defer that for now
    o1c_hash_final(st, scalar, o1c_scalar25519_BYTES);
    o1c_scalar25519_t a;
    o1c_scalar25519_clamp(a, scalar);
    o1c_ristretto255_t A;
    o1c_ristretto255_scalar_mul_base(A, a);
    o1c_ristretto255_serialize(pubkey, A);
}

void o1c_ristretto255b3_sign(uint8_t *const sig, const uint8_t *const m, const size_t m_len, const uint8_t *const key) {
    // derive scalar, pubkey, and prefix
    o1c_hash_t st;
    o1c_hash_key_setup(st, key);
    uint8_t hash[o1c_ristretto255_HASH_BYTES];
    o1c_hash_final(st, hash, o1c_ristretto255_HASH_BYTES);

    o1c_scalar25519_t a;
    o1c_scalar25519_clamp(a, hash);
    o1c_ristretto255_t A;
    o1c_ristretto255_scalar_mul_base(A, a);

    uint8_t pk[o1c_ristretto255_BYTES];
    o1c_ristretto255_serialize(pk, A);

    // Ed25519 uses SHA-512 for calculating the signature
    // this uses Blake3 in hashed mode
    o1c_hash_init(st);
    o1c_hash_update(st, hash + 32, 32);
    o1c_hash_update(st, m, m_len);
    uint8_t nonce[o1c_ristretto255_HASH_BYTES];
    o1c_hash_final(st, nonce, o1c_ristretto255_HASH_BYTES);
    o1c_scalar25519_t r;
    o1c_scalar25519_reduce(r, nonce);
    o1c_ristretto255_t R;
    o1c_ristretto255_scalar_mul_base(R, r);
    uint8_t r_bytes[o1c_ristretto255_BYTES];
    // Ed25519 compresses a point via Y/Z and a sign bit for X/Z
    // this uses the Ristretto255 encoding for compression
    o1c_ristretto255_serialize(r_bytes, R);

    // the remainder of this algorithm matches Ed25519's scalar calculation
    o1c_hash_init(st);
    o1c_hash_update(st, r_bytes, o1c_ristretto255_BYTES);
    o1c_hash_update(st, pk, o1c_ristretto255_BYTES);
    o1c_hash_update(st, m, m_len);
    o1c_hash_final(st, hash, o1c_ristretto255_HASH_BYTES);
    o1c_scalar25519_t h, s;
    o1c_scalar25519_reduce(h, hash);
    o1c_scalar25519_mul_add(s, h, a, r);
    memcpy(sig, r_bytes, 32);
    memcpy(sig + 32, s->v, 32);
}

bool o1c_ristretto255b3_verify(const uint8_t *const sig, const uint8_t *const m, const size_t m_len,
                             const uint8_t *const pk) {
    /* TODO: this implementation uses constant time algorithms where some optimizations may be allowed
     * Ideally, we can adapt ge_double_scalar_mul_vartime to work here, though the function as exists
     * does not fit properly.
     */
    o1c_ristretto255_t A, r;
    o1c_scalar25519_t s, k;

    if (!o1c_ristretto255_deserialize(r, sig) || !o1c_ristretto255_deserialize(A, pk)) return false;
    o1c_scalar25519_deserialize(s, sig + 32);
    ge_p3 sB;
    ge_scalar_mul_base(sB, s);
    ge_cached sB_cached;
    ge_ext_to_proj_niels(sB_cached, sB);

    struct extended_point negA = A->point;
    fe t;
    fe_neg(t, negA.X);
    fe_reduce(negA.X, t);
    fe_neg(t, negA.T);
    fe_reduce(negA.T, t);

    o1c_hash_t st;
    o1c_hash_init(st);
    o1c_hash_update(st, sig, 32);
    o1c_hash_update(st, pk, o1c_ristretto255_BYTES);
    o1c_hash_update(st, m, m_len);
    uint8_t hash[o1c_ristretto255_HASH_BYTES];
    o1c_hash_final(st, hash, o1c_ristretto255_HASH_BYTES);
    o1c_scalar25519_reduce(k, hash);
    ge_p3 neg_kA;
    ge_scalar_mul(neg_kA, k, &negA);
    ge_p1p1 check;
    ge_ext_add(check, neg_kA, sB_cached);
    o1c_ristretto255_t r_check;
    ge_comp_to_ext(&r_check->point, check);
    return o1c_ristretto255_equal(r_check, r);
}
