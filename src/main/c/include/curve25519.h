#pragma once

#include "scalar25519.h"

#include <stdint.h>
#include <assert.h>

#if (ARCH_WORD_BITS == 64)
#define fe_LIMBS 5
typedef uint64_t fe_limb_t;
#else
#define fe_LIMBS 10
typedef uint32_t fe_limb_t;
#endif
typedef fe_limb_t fe[fe_LIMBS];
static_assert(sizeof(fe) == sizeof(fe_limb_t) * fe_LIMBS, "fe_limb_t[fe_LIMBS] does not match fe");

void fe_add(fe h, const fe f, const fe g);

void fe_sub(fe h, const fe f, const fe g);

void fe_neg(fe h, const fe f);

void fe_reduce(fe h, const fe f);

void fe_mul(fe h, const fe f, const fe g);

void fe_mul121666(fe h, const fe f);

void fe_sqr(fe h, const fe f);

void fe_select(fe h, uint8_t b, const fe f, const fe g);

void fe_cmov(fe f, const fe g, uint8_t b);

void fe_cswap(fe f, fe g, uint8_t b);

void fe_deserialize(fe h, const uint8_t s[32]);

void fe_serialize(uint8_t s[32], const fe f);

void fe_copy(fe h, const fe f);

void fe_0(fe f);

void fe_1(fe f);

bool fe_is_neg(const fe f);

bool fe_is_nonzero(const fe f);

void fe_abs(fe h, const fe f);

void fe_invert(fe h, const fe f);

void fe_pow22523(fe h, const fe f);

typedef struct projective_point {
    fe X;
    fe Y;
    fe Z;
} ge_p2[1];

typedef struct extended_point {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p3[1];

typedef struct completed_point {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p1p1[1];

typedef struct affine_niels_point {
    fe yplusx;
    fe yminusx;
    fe xy2d;
} ge_precomp[1];

typedef struct projective_niels_point {
    fe YplusX;
    fe YminusX;
    fe Z;
    fe T2d;
} ge_cached[1];

void ge_p2_0(ge_p2 h);

void ge_p3_0(ge_p3 h);

void ge_cached_0(ge_cached h);

void ge_precomp_0(ge_precomp h);

void ge_proj_serialize(uint8_t s[32], const ge_p2 f);

void ge_ext_serialize(uint8_t s[32], const ge_p3 f);

int ge_ext_deserialize_vartime(ge_p3 h, const uint8_t s[32]);

void ge_ext_to_proj_niels(ge_cached r, const ge_p3 p);

void ge_comp_to_proj(ge_p2 r, const ge_p1p1 p);

void ge_comp_to_ext(ge_p3 r, const ge_p1p1 p);

void ge_ext_add(ge_p1p1 r, const ge_p3 p, const ge_cached q);

void ge_ext_sub(ge_p1p1 r, const ge_p3 p, const ge_cached q);

void ge_ext_madd(ge_p1p1 r, const ge_p3 p, const ge_precomp q);

void ge_ext_msub(ge_p1p1 r, const ge_p3 p, const ge_precomp q);

void ge_ext_to_proj(ge_p2 r, const ge_p3 p);

void ge_comp_to_proj_niels(ge_cached r, const ge_p1p1 p);

void ge_proj_dbl(ge_p1p1 r, const ge_p2 p);

void ge_ext_dbl(ge_p1p1 r, const ge_p3 p);

void ge_scalar_mul_base(ge_p3 h, const o1c_scalar25519_t s);

void ge_scalar_mul(ge_p3 r, const o1c_scalar25519_t s, const ge_p3 q);

void ge_double_scalar_mul_vartime(ge_p2 r, const o1c_scalar25519_t a, const ge_p3 A, const o1c_scalar25519_t b);
