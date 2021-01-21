#include <string.h>

#include "curve25519.h"
#include "curve25519/curve25519_tables.h"

#include "o1c.h"
#include "sha512.h"

#if (ARCH_WORD_BITS == 64)
#ifdef NATIVE_LITTLE_ENDIAN

#include "curve25519/fiat/curve25519_64_le.h"

#else

#include "curve25519/fiat/curve25519_64_p.h"

#endif

#else

#ifdef NATIVE_LITTLE_ENDIAN

#include "curve25519/fiat/curve25519_32_le.h"

#else

#include "curve25519/fiat/curve25519_32_p.h"

#endif

#endif

#define fe_add fiat_25519_add
#define fe_sub fiat_25519_sub
#define fe_neg fiat_25519_opp
#define fe_reduce fiat_25519_carry
#define fe_mul fiat_25519_carry_mul
#define fe_mul121666 fiat_25519_carry_scmul_121666
#define fe_sqr fiat_25519_carry_square
#define fe_select fiat_25519_selectznz
#define fe_deserialize_strict fiat_25519_from_bytes
#define fe_serialize fiat_25519_to_bytes

static inline void fe_deserialize(fe h, const uint8_t s[32]) {
    uint8_t t[32];
    memcpy(t, s, 32);
    t[31] &= 0x7f;
    fe_deserialize_strict(h, t);
}

static inline void fe_copy(fe h, const fe f) {
    memmove(h, f, sizeof(fe));
}

static inline void fe_0(fe f) {
    o1c_bzero(f, sizeof(fe));
}

static inline void fe_1(fe f) {
    o1c_bzero(f, sizeof(fe));
    f[0] = 1;
}

static inline int fe_is_neg(const fe f) {
    uint8_t tmp[o1c_scalar_BYTES];
    fe_serialize(tmp, f);
    return tmp[0] & 1;
}

static inline bool fe_is_nonzero(fe f) {
    fe tight;
    fe_reduce(tight, f);
    uint8_t tmp[o1c_field_BYTES];
    fe_serialize(tmp, tight);
    return !o1c_is_zero(tmp, o1c_field_BYTES);
}

static inline void fe_abs(fe h, const fe f) {
    fe neg_f;
    fe_neg(neg_f, f);
    fe_select(h, fe_is_neg(f), f, neg_f);
}

static inline void fe_sqr2(fe h, const fe f) {
    fe_sqr(h, f);
    fe tmp;
    fe_add(tmp, h, h);
    fe_reduce(h, tmp);
}

static void fe_invert(fe out, const fe z) {
    fe t0, t1, t2, t3;
    int i;

    fe_sqr(t0, z);
    fe_sqr(t1, t0);
    for (i = 1; i < 2; ++i) {
        fe_sqr(t1, t1);
    }
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sqr(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sqr(t2, t1);
    for (i = 1; i < 5; ++i) {
        fe_sqr(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sqr(t2, t1);
    for (i = 1; i < 10; ++i) {
        fe_sqr(t2, t2);
    }
    fe_mul(t2, t2, t1);
    fe_sqr(t3, t2);
    for (i = 1; i < 20; ++i) {
        fe_sqr(t3, t3);
    }
    fe_mul(t2, t3, t2);
    fe_sqr(t2, t2);
    for (i = 1; i < 10; ++i) {
        fe_sqr(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sqr(t2, t1);
    for (i = 1; i < 50; ++i) {
        fe_sqr(t2, t2);
    }
    fe_mul(t2, t2, t1);
    fe_sqr(t3, t2);
    for (i = 1; i < 100; ++i) {
        fe_sqr(t3, t3);
    }
    fe_mul(t2, t3, t2);
    fe_sqr(t2, t2);
    for (i = 1; i < 50; ++i) {
        fe_sqr(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sqr(t1, t1);
    for (i = 1; i < 5; ++i) {
        fe_sqr(t1, t1);
    }
    fe_mul(out, t1, t0);
}

static void fe_pow22523(fe out, const fe z) {
    fe t0;
    fe t1;
    fe t2;
    int i;

    fe_sqr(t0, z);
    fe_sqr(t1, t0);
    fe_sqr(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sqr(t0, t0);
    fe_mul(t0, t1, t0);
    fe_sqr(t1, t0);
    for (i = 1; i < 5; ++i) {
        fe_sqr(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sqr(t1, t0);
    for (i = 1; i < 10; ++i) {
        fe_sqr(t1, t1);
    }
    fe_mul(t1, t1, t0);
    fe_sqr(t2, t1);
    for (i = 1; i < 20; ++i) {
        fe_sqr(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sqr(t1, t1);
    for (i = 1; i < 10; ++i) {
        fe_sqr(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sqr(t1, t0);
    for (i = 1; i < 50; ++i) {
        fe_sqr(t1, t1);
    }
    fe_mul(t1, t1, t0);
    fe_sqr(t2, t1);
    for (i = 1; i < 100; ++i) {
        fe_sqr(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sqr(t1, t1);
    for (i = 1; i < 50; ++i) {
        fe_sqr(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sqr(t0, t0);
    fe_sqr(t0, t0);
    fe_mul(out, t0, z);
}

static void ge_p2_0(ge_p2 h) {
    fe_0(h->X);
    fe_1(h->Y);
    fe_1(h->Z);
}

static void ge_p3_0(ge_p3 h) {
    fe_0(h->X);
    fe_1(h->Y);
    fe_1(h->Z);
    fe_0(h->T);
}

static void ge_cached_0(ge_cached h) {
    fe_1(h->YplusX);
    fe_1(h->YminusX);
    fe_1(h->Z);
    fe_0(h->T2d);
}

static void ge_precomp_0(ge_precomp h) {
    fe_1(h->yplusx);
    fe_1(h->yminusx);
    fe_0(h->xy2d);
}

void ge_proj_serialize(uint8_t s[32], const ge_p2 f) {
    fe recip;
    fe x;
    fe y;

    fe_invert(recip, f->Z);
    fe_mul(x, f->X, recip);
    fe_mul(y, f->Y, recip);
    fe_serialize(s, y);
    s[31] ^= fe_is_neg(x) << 7;
}

void ge_ext_serialize(uint8_t s[32], const ge_p3 f) {
    fe recip;
    fe x;
    fe y;

    fe_invert(recip, f->Z);
    fe_mul(x, f->X, recip);
    fe_mul(y, f->Y, recip);
    fe_serialize(s, y);
    s[31] ^= fe_is_neg(x) << 7;
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

int ge_ext_deserialize_vartime(ge_p3 h, const uint8_t s[32]) {
    fe u;
    fe v;
    fe v3;
    fe vxx;
    fe check;

    fe_deserialize(h->Y, s);
    fe_1(h->Z);
    fe_sqr(v3, h->Y);
    fe_mul(vxx, v3, d);
    fe_sub(v, v3, h->Z);  // u = y^2-1
    fe_reduce(u, v);
    fe_add(v, vxx, h->Z);  // v = dy^2+1

    // TODO: use sqrt_ratio_i
    fe_sqr(v3, v);
    fe_mul(v3, v3, v);  // v3 = v^3
    fe_sqr(h->X, v3);
    fe_mul(h->X, h->X, v);
    fe_mul(h->X, h->X, u);  // x = uv^7

    fe_pow22523(h->X, h->X);  // x = (uv^7)^((q-5)/8)
    fe_mul(h->X, h->X, v3);
    fe_mul(h->X, h->X, u);  // x = uv^3(uv^7)^((q-5)/8)

    fe_sqr(vxx, h->X);
    fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u);
    if (fe_is_nonzero(check)) {
        fe_add(check, vxx, u);
        if (fe_is_nonzero(check)) {
            return 0;
        }
        fe_mul(h->X, h->X, sqrtm1);
    }

    if (fe_is_neg(h->X) != (s[31] >> 7)) {
        fe t;
        fe_neg(t, h->X);
        fe_reduce(h->X, t);
    }

    fe_mul(h->T, h->X, h->Y);
    return 1;
}

void ge_ext_to_proj_niels(ge_cached r, const ge_p3 p) {
    fe_add(r->YplusX, p->Y, p->X);
    fe_sub(r->YminusX, p->Y, p->X);
    fe_copy(r->Z, p->Z);
    fe_mul(r->T2d, p->T, d2);
}

void ge_comp_to_proj(ge_p2 r, const ge_p1p1 p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
}

void ge_comp_to_ext(ge_p3 r, const ge_p1p1 p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
    fe_mul(r->T, p->X, p->Y);
}

void ge_ext_add(ge_p1p1 r, const ge_p3 p, const ge_cached q) {
    fe trX, trY, trZ, trT;

    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(trZ, r->X, q->YplusX);
    fe_mul(trY, r->Y, q->YminusX);
    fe_mul(trT, q->T2d, p->T);
    fe_mul(trX, p->Z, q->Z);
    fe_add(r->T, trX, trX);
    fe_sub(r->X, trZ, trY);
    fe_add(r->Y, trZ, trY);
    fe_reduce(trZ, r->T);
    fe_add(r->Z, trZ, trT);
    fe_sub(r->T, trZ, trT);
}

void ge_ext_sub(ge_p1p1 r, const ge_p3 p, const ge_cached q) {
    fe trX, trY, trZ, trT;

    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(trZ, r->X, q->YminusX);
    fe_mul(trY, r->Y, q->YplusX);
    fe_mul(trT, q->T2d, p->T);
    fe_mul(trX, p->Z, q->Z);
    fe_add(r->T, trX, trX);
    fe_sub(r->X, trZ, trY);
    fe_add(r->Y, trZ, trY);
    fe_reduce(trZ, r->T);
    fe_sub(r->Z, trZ, trT);
    fe_add(r->T, trZ, trT);
}

void ge_ext_madd(ge_p1p1 r, const ge_p3 p, const ge_precomp q) {
    fe trY, trZ, trT;

    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(trZ, r->X, q->yplusx);
    fe_mul(trY, r->Y, q->yminusx);
    fe_mul(trT, q->xy2d, p->T);
    fe_add(r->T, p->Z, p->Z);
    fe_sub(r->X, trZ, trY);
    fe_add(r->Y, trZ, trY);
    fe_reduce(trZ, r->T);
    fe_add(r->Z, trZ, trT);
    fe_sub(r->T, trZ, trT);
}

void ge_ext_msub(ge_p1p1 r, const ge_p3 p, const ge_precomp q) {
    fe trY, trZ, trT;

    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(trZ, r->X, q->yminusx);
    fe_mul(trY, r->Y, q->yplusx);
    fe_mul(trT, q->xy2d, p->T);
    fe_add(r->T, p->Z, p->Z);
    fe_sub(r->X, trZ, trY);
    fe_add(r->Y, trZ, trY);
    fe_reduce(trZ, r->T);
    fe_sub(r->Z, trZ, trT);
    fe_add(r->T, trZ, trT);
}

void ge_ext_to_proj(ge_p2 r, const ge_p3 p) {
    fe_copy(r->X, p->X);
    fe_copy(r->Y, p->Y);
    fe_copy(r->Z, p->Z);
}

void ge_comp_to_proj_niels(ge_cached r, const ge_p1p1 p) {
    ge_p3 t;
    ge_comp_to_ext(t, p);
    ge_ext_to_proj_niels(r, t);
}

void ge_proj_dbl(ge_p1p1 r, const ge_p2 p) {
    fe trX, trZ, trT;
    fe t0;

    fe_sqr(trX, p->X);
    fe_sqr(trZ, p->Y);
    fe_sqr2(trT, p->Z);
    fe_add(r->Y, p->X, p->Y);
    fe_sqr(t0, r->Y);

    fe_add(r->Y, trZ, trX);
    fe_sub(r->Z, trZ, trX);
    fe_reduce(trZ, r->Y);
    fe_sub(r->X, t0, trZ);
    fe_reduce(trZ, r->Z);
    fe_sub(r->T, trT, trZ);
}

void ge_ext_dbl(ge_p1p1 r, const ge_p3 p) {
    ge_p2 q;
    ge_ext_to_proj(q, p);
    ge_proj_dbl(r, q);
}

static uint8_t equal(signed char b, signed char c) {
    uint8_t ub = b;
    uint8_t uc = c;
    uint8_t x = ub ^uc;   // 0: yes; 1..255: no
    uint32_t y = x;       // 0: yes; 1..255: no
    y -= 1;               // 4294967295: yes; 0..254: no
    y >>= 31;             // 1: yes; 0: no
    return y;
}

static uint8_t negative(signed char b) {
    uint32_t x = b;
    x >>= 31;  // 1: yes; 0: no
    return x;
}

static inline void fe_cmov(fe f, const fe g, const fe_limb_t b) {
    fe_select(f, b, f, g);
}

static void fe_cswap(fe f, fe g, fe_limb_t b) {
    b = 0 - b;
    for (unsigned int i = 0; i < fe_LIMBS; ++i) {
        fe_limb_t x = f[i] ^g[i];
        x &= b;
        f[i] ^= x;
        g[i] ^= x;
    }
}

static inline void cmov(ge_precomp t, const ge_precomp u, const fe_limb_t b) {
    fe_cmov(t->yplusx, u->yplusx, b);
    fe_cmov(t->yminusx, u->yminusx, b);
    fe_cmov(t->xy2d, u->xy2d, b);
}

static inline void cmov_pn(ge_cached t, const ge_cached u, const fe_limb_t b) {
    fe_cmov(t->YplusX, u->YplusX, b);
    fe_cmov(t->YminusX, u->YminusX, b);
    fe_cmov(t->Z, u->Z, b);
    fe_cmov(t->T2d, u->T2d, b);
}

static void table_select(ge_precomp t, const int pos, const signed char b) {
    ge_precomp minust;
    uint8_t bnegative = negative(b);
    uint8_t babs = b - ((uint8_t) ((-bnegative) & b) << 1);

    ge_precomp_0(t);
    cmov(t, &k25519Precomp[pos][0], equal(babs, 1));
    cmov(t, &k25519Precomp[pos][1], equal(babs, 2));
    cmov(t, &k25519Precomp[pos][2], equal(babs, 3));
    cmov(t, &k25519Precomp[pos][3], equal(babs, 4));
    cmov(t, &k25519Precomp[pos][4], equal(babs, 5));
    cmov(t, &k25519Precomp[pos][5], equal(babs, 6));
    cmov(t, &k25519Precomp[pos][6], equal(babs, 7));
    cmov(t, &k25519Precomp[pos][7], equal(babs, 8));
    fe_copy(minust->yplusx, t->yminusx);
    fe_copy(minust->yminusx, t->yplusx);

    // NOTE: the input table is canonical, but types don't encode it
    fe tmp;
    fe_reduce(tmp, t->xy2d);
    fe_neg(minust->xy2d, tmp);

    cmov(t, minust, bnegative);
}

void ge_scalar_mul_base(ge_p3 h, const uint8_t a[32]) {
    signed char e[64];
    signed char carry;
    ge_p1p1 r;
    ge_p2 s;
    ge_precomp t;
    int i;

    for (i = 0; i < 32; ++i) {
        e[2 * i + 0] = (a[i] >> 0) & 15;
        e[2 * i + 1] = (a[i] >> 4) & 15;
    }
    // each e[i] is between 0 and 15
    // e[63] is between 0 and 7

    carry = 0;
    for (i = 0; i < 63; ++i) {
        e[i] += carry;
        carry = e[i] + 8;
        carry >>= 4;
        e[i] -= carry << 4;
    }
    e[63] += carry;
    // each e[i] is between -8 and 8

    ge_p3_0(h);
    for (i = 1; i < 64; i += 2) {
        table_select(t, i / 2, e[i]);
        ge_ext_madd(r, h, t);
        ge_comp_to_ext(h, r);
    }

    ge_ext_dbl(r, h);
    ge_comp_to_proj(s, r);
    ge_proj_dbl(r, s);
    ge_comp_to_proj(s, r);
    ge_proj_dbl(r, s);
    ge_comp_to_proj(s, r);
    ge_proj_dbl(r, s);
    ge_comp_to_ext(h, r);

    for (i = 0; i < 64; i += 2) {
        table_select(t, i / 2, e[i]);
        ge_ext_madd(r, h, t);
        ge_comp_to_ext(h, r);
    }
}

void ge_scalar_mul(ge_p3 r, const uint8_t scalar[32], const ge_p3 q) {
    struct projective_point Ai_p2[8];
    struct projective_niels_point Ai[16];
    ge_p1p1 t;

    ge_cached_0(&Ai[0]);
    ge_ext_to_proj_niels(&Ai[1], q);
    ge_ext_to_proj(&Ai_p2[1], q);

    unsigned i;
    for (i = 2; i < 16; i += 2) {
        ge_proj_dbl(t, &Ai_p2[i / 2]);
        ge_comp_to_proj_niels(&Ai[i], t);
        if (i < 8) {
            ge_comp_to_proj(&Ai_p2[i], t);
        }
        ge_ext_add(t, q, &Ai[i]);
        ge_comp_to_proj_niels(&Ai[i + 1], t);
        if (i < 7) {
            ge_comp_to_proj(&Ai_p2[i + 1], t);
        }
    }

    ge_p2 s;
    ge_p2_0(s);
    ge_p3 u;

    for (i = 0; i < 256; i += 4) {
        ge_proj_dbl(t, s);
        ge_comp_to_proj(s, t);
        ge_proj_dbl(t, s);
        ge_comp_to_proj(s, t);
        ge_proj_dbl(t, s);
        ge_comp_to_proj(s, t);
        ge_proj_dbl(t, s);
        ge_comp_to_ext(u, t);

        uint8_t index = scalar[31 - i / 8];
        index >>= 4 - (i & 4);
        index &= 0xf;

        signed char j;
        ge_cached selected;
        ge_cached_0(selected);
        for (j = 0; j < 16; j++) {
            cmov_pn(selected, &Ai[j], equal(j, index));
        }

        ge_ext_add(t, u, selected);
        ge_comp_to_proj(s, t);
    }
    ge_comp_to_ext(r, t);
}

static void slide(signed char *r, const uint8_t *a) {
    int i;
    int b;
    int k;

    for (i = 0; i < 256; ++i) {
        r[i] = 1 & (a[i >> 3] >> (i & 7));
    }

    for (i = 0; i < 256; ++i) {
        if (r[i]) {
            for (b = 1; b <= 6 && i + b < 256; ++b) {
                if (r[i + b]) {
                    if (r[i] + (r[i + b] << b) <= 15) {
                        r[i] += r[i + b] << b;
                        r[i + b] = 0;
                    } else if (r[i] - (r[i + b] << b) >= -15) {
                        r[i] -= r[i + b] << b;
                        for (k = i + b; k < 256; ++k) {
                            if (!r[k]) {
                                r[k] = 1;
                                break;
                            }
                            r[k] = 0;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    }
}

void ge_double_scalar_mul_vartime(ge_p2 r, const uint8_t *a, const ge_p3 A, const uint8_t *b) {
    int8_t a_slide[256], b_slide[256];
    struct projective_niels_point Ai[8];
    ge_p1p1 t;
    ge_p3 u, A2;
    int i;

    slide(a_slide, a);
    slide(b_slide, b);

    ge_ext_to_proj_niels(&Ai[0], A);
    ge_ext_dbl(t, A);
    ge_comp_to_ext(A2, t);
    ge_ext_add(t, A2, &Ai[0]);
    ge_comp_to_ext(u, t);
    ge_ext_to_proj_niels(&Ai[1], u);
    ge_ext_add(t, A2, &Ai[1]);
    ge_comp_to_ext(u, t);
    ge_ext_to_proj_niels(&Ai[2], u);
    ge_ext_add(t, A2, &Ai[2]);
    ge_comp_to_ext(u, t);
    ge_ext_to_proj_niels(&Ai[3], u);
    ge_ext_add(t, A2, &Ai[3]);
    ge_comp_to_ext(u, t);
    ge_ext_to_proj_niels(&Ai[4], u);
    ge_ext_add(t, A2, &Ai[4]);
    ge_comp_to_ext(u, t);
    ge_ext_to_proj_niels(&Ai[5], u);
    ge_ext_add(t, A2, &Ai[5]);
    ge_comp_to_ext(u, t);
    ge_ext_to_proj_niels(&Ai[6], u);
    ge_ext_add(t, A2, &Ai[6]);
    ge_comp_to_ext(u, t);
    ge_ext_to_proj_niels(&Ai[7], u);

    ge_p2_0(r);
    for (i = 255; i >= 0; --i) {
        if (a_slide[i] || b_slide[i]) break;
    }
    for (; i >= 0; --i) {
        ge_proj_dbl(t, r);

        if (a_slide[i] > 0) {
            ge_comp_to_ext(u, t);
            ge_ext_add(t, u, &Ai[a_slide[i] / 2]);
        } else if (a_slide[i] < 0) {
            ge_comp_to_ext(u, t);
            ge_ext_sub(t, u, &Ai[(-a_slide[i]) / 2]);
        }

        if (b_slide[i] > 0) {
            ge_comp_to_ext(u, t);
            ge_ext_madd(t, u, &Bi[b_slide[i] / 2]);
        } else if (b_slide[i] < 0) {
            ge_comp_to_ext(u, t);
            ge_ext_msub(t, u, &Bi[(-b_slide[i]) / 2]);
        }

        ge_comp_to_proj(r, t);
    }
}

// int64_lshift21 returns |a << 21| but is defined when shifting bits into the
// sign bit. This works around a language flaw in C.
static inline int64_t int64_lshift21(int64_t a) {
    return (int64_t) ((uint64_t) a << 21);
}

static uint64_t load_3(const uint8_t *in) {
    uint64_t result;
    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;
    return result;
}

static uint64_t load_4(const uint8_t *in) {
    uint64_t result;
    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;
    result |= ((uint64_t) in[3]) << 24;
    return result;
}

void ge_scalar_mul_add(uint8_t *s, const uint8_t *a, const uint8_t *b, const uint8_t *c) {
    int64_t a0 = 2097151 & load_3(a);
    int64_t a1 = 2097151 & (load_4(a + 2) >> 5);
    int64_t a2 = 2097151 & (load_3(a + 5) >> 2);
    int64_t a3 = 2097151 & (load_4(a + 7) >> 7);
    int64_t a4 = 2097151 & (load_4(a + 10) >> 4);
    int64_t a5 = 2097151 & (load_3(a + 13) >> 1);
    int64_t a6 = 2097151 & (load_4(a + 15) >> 6);
    int64_t a7 = 2097151 & (load_3(a + 18) >> 3);
    int64_t a8 = 2097151 & load_3(a + 21);
    int64_t a9 = 2097151 & (load_4(a + 23) >> 5);
    int64_t a10 = 2097151 & (load_3(a + 26) >> 2);
    int64_t a11 = (load_4(a + 28) >> 7);
    int64_t b0 = 2097151 & load_3(b);
    int64_t b1 = 2097151 & (load_4(b + 2) >> 5);
    int64_t b2 = 2097151 & (load_3(b + 5) >> 2);
    int64_t b3 = 2097151 & (load_4(b + 7) >> 7);
    int64_t b4 = 2097151 & (load_4(b + 10) >> 4);
    int64_t b5 = 2097151 & (load_3(b + 13) >> 1);
    int64_t b6 = 2097151 & (load_4(b + 15) >> 6);
    int64_t b7 = 2097151 & (load_3(b + 18) >> 3);
    int64_t b8 = 2097151 & load_3(b + 21);
    int64_t b9 = 2097151 & (load_4(b + 23) >> 5);
    int64_t b10 = 2097151 & (load_3(b + 26) >> 2);
    int64_t b11 = (load_4(b + 28) >> 7);
    int64_t c0 = 2097151 & load_3(c);
    int64_t c1 = 2097151 & (load_4(c + 2) >> 5);
    int64_t c2 = 2097151 & (load_3(c + 5) >> 2);
    int64_t c3 = 2097151 & (load_4(c + 7) >> 7);
    int64_t c4 = 2097151 & (load_4(c + 10) >> 4);
    int64_t c5 = 2097151 & (load_3(c + 13) >> 1);
    int64_t c6 = 2097151 & (load_4(c + 15) >> 6);
    int64_t c7 = 2097151 & (load_3(c + 18) >> 3);
    int64_t c8 = 2097151 & load_3(c + 21);
    int64_t c9 = 2097151 & (load_4(c + 23) >> 5);
    int64_t c10 = 2097151 & (load_3(c + 26) >> 2);
    int64_t c11 = (load_4(c + 28) >> 7);
    int64_t s0;
    int64_t s1;
    int64_t s2;
    int64_t s3;
    int64_t s4;
    int64_t s5;
    int64_t s6;
    int64_t s7;
    int64_t s8;
    int64_t s9;
    int64_t s10;
    int64_t s11;
    int64_t s12;
    int64_t s13;
    int64_t s14;
    int64_t s15;
    int64_t s16;
    int64_t s17;
    int64_t s18;
    int64_t s19;
    int64_t s20;
    int64_t s21;
    int64_t s22;
    int64_t s23;
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;
    int64_t carry10;
    int64_t carry11;
    int64_t carry12;
    int64_t carry13;
    int64_t carry14;
    int64_t carry15;
    int64_t carry16;
    int64_t carry17;
    int64_t carry18;
    int64_t carry19;
    int64_t carry20;
    int64_t carry21;
    int64_t carry22;

    s0 = c0 + a0 * b0;
    s1 = c1 + a0 * b1 + a1 * b0;
    s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0;
    s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0;
    s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1 +
            a10 * b0;
    s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 +
            a10 * b1 + a11 * b0;
    s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 + a10 * b2 +
            a11 * b1;
    s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2;
    s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
    s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
    s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    s20 = a9 * b11 + a10 * b10 + a11 * b9;
    s21 = a10 * b11 + a11 * b10;
    s22 = a11 * b11;
    s23 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= int64_lshift21(carry12);
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= int64_lshift21(carry14);
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= int64_lshift21(carry16);
    carry18 = (s18 + (1 << 20)) >> 21;
    s19 += carry18;
    s18 -= int64_lshift21(carry18);
    carry20 = (s20 + (1 << 20)) >> 21;
    s21 += carry20;
    s20 -= int64_lshift21(carry20);
    carry22 = (s22 + (1 << 20)) >> 21;
    s23 += carry22;
    s22 -= int64_lshift21(carry22);

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= int64_lshift21(carry13);
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= int64_lshift21(carry15);
    carry17 = (s17 + (1 << 20)) >> 21;
    s18 += carry17;
    s17 -= int64_lshift21(carry17);
    carry19 = (s19 + (1 << 20)) >> 21;
    s20 += carry19;
    s19 -= int64_lshift21(carry19);
    carry21 = (s21 + (1 << 20)) >> 21;
    s22 += carry21;
    s21 -= int64_lshift21(carry21);

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    s22 = 0;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    s21 = 0;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    s20 = 0;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    s19 = 0;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    s18 = 0;

    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= int64_lshift21(carry12);
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= int64_lshift21(carry14);
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= int64_lshift21(carry16);

    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= int64_lshift21(carry13);
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= int64_lshift21(carry15);

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    s17 = 0;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    s16 = 0;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    s15 = 0;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    s14 = 0;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    s13 = 0;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);

    s[0] = s0 >> 0;
    s[1] = s0 >> 8;
    s[2] = (s0 >> 16) | (s1 << 5);
    s[3] = s1 >> 3;
    s[4] = s1 >> 11;
    s[5] = (s1 >> 19) | (s2 << 2);
    s[6] = s2 >> 6;
    s[7] = (s2 >> 14) | (s3 << 7);
    s[8] = s3 >> 1;
    s[9] = s3 >> 9;
    s[10] = (s3 >> 17) | (s4 << 4);
    s[11] = s4 >> 4;
    s[12] = s4 >> 12;
    s[13] = (s4 >> 20) | (s5 << 1);
    s[14] = s5 >> 7;
    s[15] = (s5 >> 15) | (s6 << 6);
    s[16] = s6 >> 2;
    s[17] = s6 >> 10;
    s[18] = (s6 >> 18) | (s7 << 3);
    s[19] = s7 >> 5;
    s[20] = s7 >> 13;
    s[21] = s8 >> 0;
    s[22] = s8 >> 8;
    s[23] = (s8 >> 16) | (s9 << 5);
    s[24] = s9 >> 3;
    s[25] = s9 >> 11;
    s[26] = (s9 >> 19) | (s10 << 2);
    s[27] = s10 >> 6;
    s[28] = (s10 >> 14) | (s11 << 7);
    s[29] = s11 >> 1;
    s[30] = s11 >> 9;
    s[31] = s11 >> 17;
}

void ge_scalar_reduce(uint8_t s[64]) {
    int64_t s0 = 2097151 & load_3(s);
    int64_t s1 = 2097151 & (load_4(s + 2) >> 5);
    int64_t s2 = 2097151 & (load_3(s + 5) >> 2);
    int64_t s3 = 2097151 & (load_4(s + 7) >> 7);
    int64_t s4 = 2097151 & (load_4(s + 10) >> 4);
    int64_t s5 = 2097151 & (load_3(s + 13) >> 1);
    int64_t s6 = 2097151 & (load_4(s + 15) >> 6);
    int64_t s7 = 2097151 & (load_3(s + 18) >> 3);
    int64_t s8 = 2097151 & load_3(s + 21);
    int64_t s9 = 2097151 & (load_4(s + 23) >> 5);
    int64_t s10 = 2097151 & (load_3(s + 26) >> 2);
    int64_t s11 = 2097151 & (load_4(s + 28) >> 7);
    int64_t s12 = 2097151 & (load_4(s + 31) >> 4);
    int64_t s13 = 2097151 & (load_3(s + 34) >> 1);
    int64_t s14 = 2097151 & (load_4(s + 36) >> 6);
    int64_t s15 = 2097151 & (load_3(s + 39) >> 3);
    int64_t s16 = 2097151 & load_3(s + 42);
    int64_t s17 = 2097151 & (load_4(s + 44) >> 5);
    int64_t s18 = 2097151 & (load_3(s + 47) >> 2);
    int64_t s19 = 2097151 & (load_4(s + 49) >> 7);
    int64_t s20 = 2097151 & (load_4(s + 52) >> 4);
    int64_t s21 = 2097151 & (load_3(s + 55) >> 1);
    int64_t s22 = 2097151 & (load_4(s + 57) >> 6);
    int64_t s23 = (load_4(s + 60) >> 3);
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;
    int64_t carry10;
    int64_t carry11;
    int64_t carry12;
    int64_t carry13;
    int64_t carry14;
    int64_t carry15;
    int64_t carry16;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    s22 = 0;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    s21 = 0;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    s20 = 0;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    s19 = 0;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    s18 = 0;

    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= int64_lshift21(carry12);
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= int64_lshift21(carry14);
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= int64_lshift21(carry16);

    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= int64_lshift21(carry13);
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= int64_lshift21(carry15);

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    s17 = 0;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    s16 = 0;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    s15 = 0;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    s14 = 0;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    s13 = 0;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);

    s[0] = s0 >> 0;
    s[1] = s0 >> 8;
    s[2] = (s0 >> 16) | (s1 << 5);
    s[3] = s1 >> 3;
    s[4] = s1 >> 11;
    s[5] = (s1 >> 19) | (s2 << 2);
    s[6] = s2 >> 6;
    s[7] = (s2 >> 14) | (s3 << 7);
    s[8] = s3 >> 1;
    s[9] = s3 >> 9;
    s[10] = (s3 >> 17) | (s4 << 4);
    s[11] = s4 >> 4;
    s[12] = s4 >> 12;
    s[13] = (s4 >> 20) | (s5 << 1);
    s[14] = s5 >> 7;
    s[15] = (s5 >> 15) | (s6 << 6);
    s[16] = s6 >> 2;
    s[17] = s6 >> 10;
    s[18] = (s6 >> 18) | (s7 << 3);
    s[19] = s7 >> 5;
    s[20] = s7 >> 13;
    s[21] = s8 >> 0;
    s[22] = s8 >> 8;
    s[23] = (s8 >> 16) | (s9 << 5);
    s[24] = s9 >> 3;
    s[25] = s9 >> 11;
    s[26] = (s9 >> 19) | (s10 << 2);
    s[27] = s10 >> 6;
    s[28] = (s10 >> 14) | (s11 << 7);
    s[29] = s11 >> 1;
    s[30] = s11 >> 9;
    s[31] = s11 >> 17;
}

static bool ge_scalar_is_canonical(const o1c_scalar_t s) {
    /* 2^252+27742317777372353535851937790883648493 */
    static const uint8_t L[32] = {
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
            0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    uint8_t c = 0;
    uint8_t n = 1;
    unsigned int i = 32;

    do {
        i--;
        c |= ((s->v[i] - L[i]) >> 8) & n;
        n &= ((s->v[i] ^ L[i]) - 1) >> 8;
    } while (i != 0);

    return (c != 0);
}

void o1c_scalar_random(o1c_scalar_t s) {
    do {
        drbg_randombytes(s->v, o1c_scalar_BYTES);
        s->v[o1c_scalar_BYTES - 1] &= 0x1f;
    } while (!ge_scalar_is_canonical(s) || o1c_is_zero(s->v, o1c_scalar_BYTES));
}

void o1c_field_scalar_keypair(uint8_t pk[o1c_field_BYTES], uint8_t sk[o1c_scalar_BYTES]) {
    drbg_randombytes(sk, o1c_scalar_BYTES);
    o1c_field_scalar_mul_base(pk, sk);
}

void o1c_field_scalar_mul_base(uint8_t q[o1c_field_BYTES], const uint8_t n[o1c_scalar_BYTES]) {
    uint8_t t[o1c_scalar_BYTES];
    memcpy(t, n, o1c_scalar_BYTES);
    t[0] &= 248;
    t[31] &= 127;
    t[31] |= 64;
    ge_p3 Q;
    ge_scalar_mul_base(Q, t);
    fe zplusy, zminusy, zminusy_inv;
    fe_add(zplusy, Q->Z, Q->Y);
    fe_sub(zminusy, Q->Z, Q->Y);
    fe_invert(zminusy_inv, zminusy);
    fe_mul(zminusy_inv, zplusy, zminusy_inv);
    fe_serialize(q, zminusy_inv);
}

bool
o1c_field_scalar_mul(uint8_t q[o1c_field_BYTES], const uint8_t n[o1c_scalar_BYTES], const uint8_t p[o1c_field_BYTES]) {
    fe x1, x2, z2, x3, z3, tmp0, tmp1, x2l, z2l, x3l, tmp0l, tmp1l;
    unsigned swap = 0;
    uint8_t t[o1c_scalar_BYTES];

    memcpy(t, n, o1c_scalar_BYTES);
    t[0] &= 248;
    t[31] &= 127;
    t[31] |= 64;

    fe_deserialize(x1, p);
    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    for (int pos = 254; pos >= 0; --pos) {
        unsigned b = 1 & (t[pos / 8] >> (pos & 7));
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;
        fe_sub(tmp0l, x3, z3);
        fe_sub(tmp1l, x2, z2);
        fe_add(x2l, x2, z2);
        fe_add(z2l, x3, z3);
        fe_mul(z3, tmp0l, x2l);
        fe_mul(z2, z2l, tmp1l);
        fe_sqr(tmp0, tmp1l);
        fe_sqr(tmp1, x2l);
        fe_add(x3l, z3, z2);
        fe_sub(z2l, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1l, tmp1, tmp0);
        fe_sqr(z2, z2l);
        fe_mul121666(z3, tmp1l);
        fe_sqr(x3, x3l);
        fe_add(tmp0l, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1l, tmp0l);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_serialize(q, x2);
    return !o1c_is_zero(q, o1c_field_BYTES);
}

void o1c_sign_seed_keypair(uint8_t pk[o1c_sign_KEY_BYTES], uint8_t sk[o1c_sign_KEYPAIR_BYTES],
                           const uint8_t seed[o1c_sign_KEY_BYTES]) {
    uint8_t az[sha512_HASH_BYTES];
    sha512(az, seed, o1c_sign_KEY_BYTES);
    az[0] &= 248;
    az[31] &= 127;
    az[31] |= 64;
    ge_p3 A;
    ge_scalar_mul_base(A, az);
    ge_ext_serialize(pk, A);
    memmove(sk, seed, 32);
    memmove(sk + 32, pk, 32);
}

void o1c_sign_keypair(uint8_t pk[o1c_sign_KEY_BYTES], uint8_t sk[o1c_sign_KEYPAIR_BYTES]) {
    uint8_t seed[32];
    drbg_randombytes(seed, 32);
    o1c_sign_seed_keypair(pk, sk, seed);
    o1c_bzero(seed, 32);
}

void
o1c_sign_detached(uint8_t s[o1c_sign_BYTES], const uint8_t *m, unsigned long len,
                  const uint8_t sk[o1c_sign_KEYPAIR_BYTES]) {
    uint8_t az[sha512_HASH_BYTES];
    sha512(az, sk, 32);
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    sha512_ctx_t ctx;
    sha512_init(ctx);
    sha512_update(ctx, az + 32, 32);
    sha512_update(ctx, m, len);
    uint8_t nonce[sha512_HASH_BYTES];
    sha512_final(ctx, nonce);
    ge_scalar_reduce(nonce);
    ge_p3 R;
    ge_scalar_mul_base(R, nonce);
    ge_ext_serialize(s, R);
    sha512_init(ctx);
    sha512_update(ctx, s, 32);
    sha512_update(ctx, sk + 32, 32);
    sha512_update(ctx, m, len);
    uint8_t hram[sha512_HASH_BYTES];
    sha512_final(ctx, hram);
    ge_scalar_reduce(hram);
    ge_scalar_mul_add(s + 32, hram, az, nonce);
}

bool
o1c_sign_verify_detached(const uint8_t s[o1c_sign_BYTES], const uint8_t *m, unsigned long len,
                         const uint8_t pk[o1c_sign_KEY_BYTES]) {
    ge_p3 A;
    if ((s[63] & 224) != 0 || !ge_ext_deserialize_vartime(A, pk)) {
        return false;
    }
    fe t;
    fe_neg(t, A->X);
    fe_reduce(A->X, t);
    fe_neg(t, A->T);
    fe_reduce(A->T, t);
    uint8_t pk_copy[o1c_sign_KEY_BYTES];
    memcpy(pk_copy, pk, o1c_sign_KEY_BYTES);
    uint8_t r_copy[32];
    memcpy(r_copy, s, 32);
    union {
        uint64_t u64[4];
        uint8_t u8[32];
    } s_copy;
    memcpy(&s_copy.u8[0], s + 32, 32);
    static const uint64_t kOrder[4] = {
            UINT64_C(0x5812631a5cf5d3ed),
            UINT64_C(0x14def9dea2f79cd6),
            0,
            UINT64_C(0x1000000000000000),
    };
    for (unsigned i = 3;; i--) {
        if (s_copy.u64[i] > kOrder[i] || i == 0) return false;
        if (s_copy.u64[i] < kOrder[i]) break;
    }
    sha512_ctx_t ctx;
    sha512_init(ctx);
    sha512_update(ctx, s, 32);
    sha512_update(ctx, pk, 32);
    sha512_update(ctx, m, len);
    uint8_t hash[sha512_HASH_BYTES];
    sha512_final(ctx, hash);
    ge_scalar_reduce(hash);
    ge_p2 R;
    ge_double_scalar_mul_vartime(R, hash, A, s_copy.u8);
    uint8_t r_check[32];
    ge_proj_serialize(r_check, R);
    return o1c_mem_eq(r_check, r_copy, 32);
}

static bool po_group_is_canonical(const o1c_po_group_element_t f) {
    uint8_t C, D, E;
    unsigned int i;
    C = (f->v[31] & 0x7f) ^ 0x7f;
    for (i = 30; i > 0; i--) {
        C |= f->v[i] ^ 0xff;
    }
    C = (((unsigned int) C) - 1U) >> 8;
    D = (0xed - 1U - (unsigned int) f->v[0]) >> 8;
    E = f->v[31] >> 7;

    return 1 - (((C & D) | E | f->v[0]) & 1);
}

// https://ristretto.group/formulas/decoding.html
static bool po_group_deserialize(ge_p3 h, const o1c_po_group_element_t f) {
    fe inv_sqrt, one, s, ss, u1, u2, u1u1, u2u2, v, v_u2u2;
    if (!po_group_is_canonical(f)) return false;

    fe_deserialize(s, f->v);
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
static void po_group_serialize(o1c_po_group_element_t f, const ge_p3 p) {
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
    fe_serialize(f->v, zmy);
}

// https://ristretto.group/formulas/elligator.html
static void po_group_elligator(ge_p3 p, const fe t) {
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

void o1c_po_group_keypair(o1c_po_group_element_t pk, o1c_scalar_t sk) {
    o1c_scalar_random(sk);
    (void) o1c_po_group_scalar_mul_base(pk, sk);
}

bool o1c_po_group_scalar_mul(o1c_po_group_element_t q, const o1c_scalar_t n, const o1c_po_group_element_t p) {
    ge_p3 Q, P;
    if (!po_group_deserialize(P, p)) return false;
    uint8_t t[o1c_scalar_BYTES];
    memcpy(t, n->v, o1c_scalar_BYTES);
    t[31] &= 0x7f;
    ge_scalar_mul(Q, t, P);
    po_group_serialize(q, Q);
    return !o1c_is_zero(q->v, sizeof(o1c_po_group_element_s));
}

bool o1c_po_group_scalar_mul_base(o1c_po_group_element_t q, const o1c_scalar_t n) {
    ge_p3 Q;
    uint8_t t[o1c_scalar_BYTES];
    memcpy(t, n->v, o1c_scalar_BYTES);
    t[31] &= 0x7f;
    ge_scalar_mul_base(Q, t);
    po_group_serialize(q, Q);
    return !o1c_is_zero(q->v, sizeof(o1c_po_group_element_s));
}

void o1c_po_group_element_from_hash(o1c_po_group_element_t q, const uint8_t h[o1c_po_group_element_HASH_BYTES]) {
    fe r0, r1;
    fe_deserialize(r0, h);
    fe_deserialize(r1, h + o1c_field_BYTES);
    ge_p3 p0, p1;
    po_group_elligator(p0, r0);
    po_group_elligator(p1, r1);
    ge_cached p1_cached;
    ge_ext_to_proj_niels(p1_cached, p1);
    ge_p1p1 p1_p1p1;
    ge_ext_add(p1_p1p1, p0, p1_cached);
    ge_p3 p;
    ge_comp_to_ext(p, p1_p1p1);
    po_group_serialize(q, p);
}
