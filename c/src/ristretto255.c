#include "ristretto255.h"
#include "curve25519.h"
#include "util.h"

// TODO: separate constants
#include "curve25519/curve25519_tables.h"

#include <string.h>

void o1c_ristretto255_scalar_random(o1c_ristretto255_scalar_t s) {
    o1c_scalar25519_t scalar;
    o1c_scalar25519_random(scalar);
    memcpy(s->v, scalar->v, o1c_ristretto255_SCALAR_BYTES);
}

void o1c_ristretto255_keypair(o1c_ristretto255_element_t pk, o1c_ristretto255_scalar_t sk) {
    o1c_ristretto255_scalar_random(sk);
    assert(o1c_ristretto255_scalar_mul_base(pk, sk));
}

static bool ristretto_is_canonical(const uint8_t f[o1c_ristretto255_ELEMENT_BYTES]) {
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
static bool ristretto_deserialize(ge_p3 h, const uint8_t f[o1c_ristretto255_ELEMENT_BYTES]) {
    fe inv_sqrt, one, s, ss, u1, u2, u1u1, u2u2, v, v_u2u2;
    if (!ristretto_is_canonical(f)) return false;

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
    fe_mul(h->X, inv_sqrt, u2);

    fe_mul(h->Y, inv_sqrt, h->X);
    fe_mul(h->Y, h->Y, v);
    fe_mul(h->Y, h->Y, u1);

    fe_mul(h->X, h->X, s);
    fe_add(h->X, h->X, h->X);
    fe_abs(h->X, h->X);
    fe_mul(h->T, h->X, h->Y);
    fe_1(h->Z);
    return ((1 - ratio_is_square) | fe_is_neg(h->T) | !fe_is_nonzero(h->Y)) == 0;
}

// https://ristretto.group/formulas/encoding.html
static void ristretto_serialize(uint8_t f[o1c_ristretto255_ELEMENT_BYTES], const ge_p3 p) {
    fe u1;
    fe_add(u1, p->Z, p->Y); // Z+Y
    fe zmy;
    fe_sub(zmy, p->Z, p->Y); // Z-Y
    fe_mul(u1, u1, zmy); // (Z+Y)*(Z-Y)
    fe u2;
    fe_mul(u2, p->X, p->Y); // X*Y
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
    fe_mul(z_inv, z_inv, p->T); // den1*den2*T
    fe ix;
    fe_mul(ix, p->X, sqrtm1); // X*sqrt(-1)
    fe iy;
    fe_mul(iy, p->Y, sqrtm1); // Y*sqrt(-1)
    fe eden;
    fe_mul(eden, den1, invsqrtamd); // den1/sqrt(a-d)
    fe t_z_inv;
    fe_mul(t_z_inv, p->T, z_inv); // T*z_inv

    bool rotate = (bool) fe_is_neg(t_z_inv);
    fe x, y, den_inv;
    fe_select(x, rotate, p->X, iy);
    fe_select(y, rotate, p->Y, ix);
    fe_select(den_inv, rotate, den2, eden);

    fe x_z_inv;
    fe_mul(x_z_inv, x, z_inv);
    fe y_neg;
    fe_neg(y_neg, y);
    fe_cmov(y, y_neg, fe_is_neg(x_z_inv));

    fe_sub(zmy, p->Z, y);
    fe_mul(zmy, zmy, den_inv);
    fe_abs(zmy, zmy);
    fe_reduce(zmy, zmy);
    fe_serialize(f, zmy);
}

// https://ristretto.group/formulas/elligator.html
static void ristretto_elligator(ge_p3 p, const fe t) {
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

    fe_mul(p->X, w0, w3);
    fe_mul(p->Y, w2, w1);
    fe_mul(p->Z, w1, w3);
    fe_mul(p->T, w0, w2);
}

#ifdef TODO_SIGNCRYPT
static bool
ristretto_add(o1c_ristretto255_element_t r, const o1c_ristretto255_element_t p, const o1c_ristretto255_element_t q) {
    ge_p3 p_p3, q_p3, r_p3;
    if (!ristretto_deserialize(p_p3, p->v) || !ristretto_deserialize(q_p3, q->v)) return false;
    ge_cached q_cached;
    ge_ext_to_proj_niels(q_cached, q_p3);
    ge_p1p1 r_p1p1;
    ge_ext_add(r_p1p1, p_p3, q_cached);
    ge_comp_to_ext(r_p3, r_p1p1);
    ristretto_serialize(r->v, r_p3);
    return true;
}
#endif

void o1c_ristretto255_from_hash(o1c_ristretto255_element_t q, const uint8_t h[o1c_ristretto255_HASH_BYTES]) {
    fe r0, r1;
    fe_deserialize(r0, h);
    fe_deserialize(r1, h + o1c_ristretto255_ELEMENT_BYTES);
    ge_p3 p0, p1;
    ristretto_elligator(p0, r0);
    ristretto_elligator(p1, r1);
    ge_cached p1_cached;
    ge_ext_to_proj_niels(p1_cached, p1);
    ge_p1p1 p1_p1p1;
    ge_ext_add(p1_p1p1, p0, p1_cached);
    ge_p3 p;
    ge_comp_to_ext(p, p1_p1p1);
    ristretto_serialize(q->v, p);
}

bool o1c_ristretto255_scalar_mul(o1c_ristretto255_element_t q, const o1c_ristretto255_scalar_t n,
                                 const o1c_ristretto255_element_t p) {
    ge_p3 Q, P;
    if (!ristretto_deserialize(P, p->v)) return false;
    o1c_scalar25519_t t;
    memcpy(t->v, n->v, o1c_ristretto255_SCALAR_BYTES);
    t->v[31] &= 0x7f;
    ge_scalar_mul(Q, t, P);
    ristretto_serialize(q->v, Q);
    return !o1c_is_zero(q->v, o1c_ristretto255_ELEMENT_BYTES);
}

bool o1c_ristretto255_scalar_mul_base(o1c_ristretto255_element_t q, const o1c_ristretto255_scalar_t n) {
    ge_p3 Q;
    o1c_scalar25519_t t;
    memcpy(t->v, n->v, o1c_ristretto255_SCALAR_BYTES);
    t->v[31] &= 0x7f;
    ge_scalar_mul_base(Q, t);
    ristretto_serialize(q->v, Q);
    return !o1c_is_zero(q->v, o1c_ristretto255_ELEMENT_BYTES);
}

#ifdef TODO_SIGNCRYPT
static const uint8_t SHARED_KEY[] = {'s', 'h', 'a', 'r', 'e', 'd', '_', 'k', 'e', 'y'};
static const uint8_t SIGN_KEY[] = {'s', 'i', 'g', 'n', '_', 'k', 'e', 'y'};

static inline void rsc_hash(o1c_hash_t st, const uint8_t *sender_id, const size_t sender_id_len,
                            const uint8_t *recipient_id, const size_t recipient_id_len,
                            const uint8_t *context, const size_t context_len) {
    uint8_t size = (uint8_t) sender_id_len;
    o1c_hash_update(st, &size, 1);
    o1c_hash_update(st, sender_id, sender_id_len);
    size = (uint8_t) recipient_id_len;
    o1c_hash_update(st, &size, 1);
    o1c_hash_update(st, recipient_id, recipient_id_len);
    size = (uint8_t) context_len;
    o1c_hash_update(st, &size, 1);
    o1c_hash_update(st, context, context_len);
}

/*
given sender keys W_a = w_a * G with id_a, and recipient keys W_b = w_b * G with id_b
1. validate recipient certificate if used
2. select random scalar r
3. compute R = r * G where G is the generator element; let R = (x_r, y_r) in compressed x/y coordinates
4. given key size in bits f (256 in ed25519), let x_r' = 2^ceil(f/2) + (x_r % 2^ceil(f/2))
(or x_r' = 2^128 + (x_r % 2^128)
compute K = (r + x_r' * w_a) * W_b, where K = (x_K, y_K) in compressed coordinates
if K is the identity element, retry back to #2.
let session key k = H(x_K || id_a || y_K || id_b)
5. compute ciphertext C = E_k(M)
6. compute t = H(C || x_r || id_a || y_r || id_b)
compute s = (t * w_a - r) % n
7. send signcrypted (R, C, s)
 */
bool
o1c_ristretto255_signcrypt(const o1c_ristretto255_aead_t aead, uint8_t sig[o1c_ristretto255_SIGN_BYTES], uint8_t *tag,
                           uint8_t *c, const uint8_t *m, size_t m_len, const uint8_t *ad, size_t ad_len,
                           const uint8_t *nonce,
                           const uint8_t *sender_id, size_t sender_id_len,
                           const uint8_t *recipient_id, size_t recipient_id_len,
                           const uint8_t *context, size_t context_len,
                           const o1c_ristretto255_scalar_t sender_sk,
                           const o1c_ristretto255_element_t recipient_pk) {
    if (sender_id_len > 255 || recipient_id_len > 255 || context_len > 255) return false;

    o1c_ristretto255_scalar_t r, ks;
    o1c_ristretto255_element_t R, kp;
    o1c_ristretto255_scalar_random(r);
    if (!o1c_ristretto255_scalar_mul_base(R, r)) return false;

    // Toorani-Beheshti signcryption would normally need to reduce this element r to create a scalar, but with
    // ristretto, we can use point encoding to do the same
    ge_scalar_mul_add(ks->v, sender_sk->v, R->v, r->v);
    if (!o1c_ristretto255_scalar_mul(kp, ks, recipient_pk)) return false;
    o1c_hash_t st;
    o1c_hash_init(st);
    o1c_hash_update(st, SHARED_KEY, sizeof SHARED_KEY);
    o1c_hash_update(st, kp->v, o1c_ristretto255_ELEMENT_BYTES);
    rsc_hash(st, sender_id, sender_id_len, recipient_id, recipient_id_len, context, context_len);
    uint8_t shared[aead->key_bytes];
    o1c_hash_final(st, shared, aead->key_bytes);

    o1c_hash_init(st);
    o1c_hash_update(st, SIGN_KEY, sizeof SIGN_KEY);
    o1c_hash_update(st, R->v, o1c_ristretto255_ELEMENT_BYTES);
    rsc_hash(st, sender_id, sender_id_len, recipient_id, recipient_id_len, context, context_len);
    aead->encrypt(c, tag, m, m_len, ad, ad_len, nonce, shared);
    o1c_hash_update(st, c, m_len);
    uint8_t hash[o1c_ristretto255_HASH_BYTES];
    o1c_hash_final(st, hash, o1c_ristretto255_HASH_BYTES);
    ge_scalar_reduce(hash);
    o1c_ristretto255_scalar_t challenge;
    memcpy(challenge->v, hash, o1c_ristretto255_SCALAR_BYTES);

    uint8_t neg_nonce[o1c_ristretto255_SCALAR_BYTES];
    scalar_negate(neg_nonce, r->v);
    ge_scalar_mul_add(sig + o1c_ristretto255_ELEMENT_BYTES, challenge->v, sender_sk->v, neg_nonce);
    memcpy(sig, R->v, o1c_ristretto255_ELEMENT_BYTES);
    return true;
}

/*
given signcrypted message (R, C, s)
compute K = w_b * (R + x_r' * W_a) = (x_K, y_K)
compute k = H(x_K || id_a || y_K || id_b)
decrypt M = D_k(C)
compute t = H(C || x_r || id_a || y_r || id_b)
verify that s * G + R = t * W_a
 */
bool
o1c_ristretto255_signcrypt_open(const o1c_ristretto255_aead_t aead,
                                const uint8_t sig[o1c_ristretto255_SIGN_BYTES], const uint8_t *tag,
                                uint8_t *m, const uint8_t *c, size_t c_len, const uint8_t *ad, size_t ad_len,
                                const uint8_t *nonce,
                                const uint8_t *sender_id, size_t sender_id_len,
                                const uint8_t *recipient_id, size_t recipient_id_len,
                                const uint8_t *context, size_t context_len,
                                const o1c_ristretto255_element_t sender_pk,
                                const o1c_ristretto255_scalar_t recipient_sk) {
    if (sender_id_len > 255 || recipient_id_len > 255 || context_len > 255 ||
        !ge_scalar_is_canonical(sig + o1c_ristretto255_ELEMENT_BYTES)) {
        return false;
    }
    o1c_ristretto255_scalar_t rs;
    memcpy(rs->v, sig, o1c_ristretto255_SCALAR_BYTES);
    o1c_ristretto255_element_t kp, R;
    memcpy(R->v, sig, o1c_ristretto255_ELEMENT_BYTES);
    if (!o1c_ristretto255_scalar_mul(kp, rs, sender_pk) ||
        !ristretto_add(kp, R, kp) ||
        !o1c_ristretto255_scalar_mul(kp, recipient_sk, kp)) {
        return false;
    }

    o1c_hash_t st;
    o1c_hash_init(st);
    o1c_hash_update(st, SHARED_KEY, sizeof SHARED_KEY);
    o1c_hash_update(st, kp->v, o1c_ristretto255_ELEMENT_BYTES);
    rsc_hash(st, sender_id, sender_id_len, recipient_id, recipient_id_len, context, context_len);
    uint8_t shared[aead->key_bytes];
    o1c_hash_final(st, shared, aead->key_bytes);

    o1c_hash_init(st);
    o1c_hash_update(st, SIGN_KEY, sizeof SIGN_KEY);
    o1c_hash_update(st, sig, o1c_ristretto255_ELEMENT_BYTES);
    rsc_hash(st, sender_id, sender_id_len, recipient_id, recipient_id_len, context, context_len);
    if (!aead->decrypt(m, tag, c, c_len, ad, ad_len, nonce, shared)) return false;
    o1c_hash_update(st, c, c_len);
    uint8_t hash[o1c_ristretto255_HASH_BYTES];
    o1c_hash_final(st, hash, o1c_ristretto255_HASH_BYTES);
    ge_scalar_reduce(hash);
    o1c_ristretto255_scalar_t challenge;
    memcpy(challenge->v, hash, o1c_ristretto255_SCALAR_BYTES);
    o1c_ristretto255_element_t expected, actual;
    o1c_ristretto255_scalar_t S;
    memcpy(S->v, sig + o1c_ristretto255_ELEMENT_BYTES, o1c_ristretto255_SCALAR_BYTES);
    return o1c_ristretto255_scalar_mul_base(expected, S) &&
           ristretto_add(expected, expected, R) &&
           o1c_ristretto255_scalar_mul(actual, challenge, sender_pk) &&
           o1c_mem_eq(expected->v, actual->v, o1c_ristretto255_ELEMENT_BYTES);
}
#endif
