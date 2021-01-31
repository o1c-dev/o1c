#include "curve25519.h"
#include "curve25519/curve25519_tables.h"
#include "util.h"

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

#include <string.h>

void fe_add(fe h, const fe f, const fe g) {
    fiat_25519_add(h, f, g);
}

void fe_sub(fe h, const fe f, const fe g) {
    fiat_25519_sub(h, f, g);
}

void fe_neg(fe h, const fe f) {
    fiat_25519_opp(h, f);
}

void fe_reduce(fe h, const fe f) {
    fiat_25519_carry(h, f);
}

void fe_mul(fe h, const fe f, const fe g) {
    fiat_25519_carry_mul(h, f, g);
}

void fe_mul121666(fe h, const fe f) {
    fiat_25519_carry_scmul_121666(h, f);
}

void fe_sqr(fe h, const fe f) {
    fiat_25519_carry_square(h, f);
}

void fe_select(fe h, uint8_t b, const fe f, const fe g) {
    fiat_25519_selectznz(h, b, f, g);
}

void fe_deserialize(fe h, const uint8_t s[32]) {
    uint8_t t[32];
    memcpy(t, s, 32);
    t[31] &= 0x7f;
    fiat_25519_from_bytes(h, t);
}

void fe_serialize(uint8_t s[32], const fe f) {
    fiat_25519_to_bytes(s, f);
}

void fe_copy(fe h, const fe f) {
    memmove(h, f, sizeof(fe));
}

void fe_0(fe f) {
    o1c_bzero(f, sizeof(fe));
}

void fe_1(fe f) {
    o1c_bzero(f, sizeof(fe));
    f[0] = 1;
}

bool fe_is_neg(const fe f) {
    uint8_t tmp[32];
    fe_serialize(tmp, f);
    return tmp[0] & 1;
}

bool fe_is_nonzero(const fe f) {
    fe tight;
    fe_reduce(tight, f);
    uint8_t tmp[32];
    fe_serialize(tmp, tight);
    return !o1c_is_zero(tmp, 32);
}

void fe_abs(fe h, const fe f) {
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

void fe_invert(fe out, const fe z) {
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

void fe_pow22523(fe out, const fe z) {
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

void fe_cmov(fe f, const fe g, const uint8_t b) {
    fe_select(f, b, f, g);
}

void fe_cswap(fe f, fe g, const uint8_t b) {
    fe_limb_t mask = 0 - (fe_limb_t) b;
    for (unsigned int i = 0; i < fe_LIMBS; ++i) {
        fe_limb_t x = f[i] ^g[i];
        x &= mask;
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

void ge_p2_0(ge_p2 h) {
    fe_0(h->X);
    fe_1(h->Y);
    fe_1(h->Z);
}

void ge_p3_0(ge_p3 h) {
    fe_0(h->X);
    fe_1(h->Y);
    fe_1(h->Z);
    fe_0(h->T);
}

void ge_cached_0(ge_cached h) {
    fe_1(h->YplusX);
    fe_1(h->YminusX);
    fe_1(h->Z);
    fe_0(h->T2d);
}

void ge_precomp_0(ge_precomp h) {
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

void ge_scalar_mul_base(ge_p3 h, const o1c_scalar25519_t a) {
    signed char e[64];
    signed char carry;
    ge_p1p1 r;
    ge_p2 s;
    ge_precomp t;
    int i;

    for (i = 0; i < 32; ++i) {
        e[2 * i + 0] = (a->v[i] >> 0) & 15;
        e[2 * i + 1] = (a->v[i] >> 4) & 15;
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

void ge_scalar_mul(ge_p3 r, const o1c_scalar25519_t scalar, const ge_p3 q) {
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

        uint8_t index = scalar->v[31 - i / 8];
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

void ge_double_scalar_mul_vartime(ge_p2 r, const o1c_scalar25519_t a, const ge_p3 A, const o1c_scalar25519_t b) {
    int8_t a_slide[256], b_slide[256];
    struct projective_niels_point Ai[8];
    ge_p1p1 t;
    ge_p3 u, A2;
    int i;

    slide(a_slide, a->v);
    slide(b_slide, b->v);

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
