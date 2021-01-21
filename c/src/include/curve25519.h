#ifndef O1C_CURVE25519_H
#define O1C_CURVE25519_H

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

void ge_proj_serialize(uint8_t s[32], const ge_p2 f);

void ge_ext_serialize(uint8_t s[32], const ge_p3 f);

int ge_ext_deserialize_vartime(ge_p3 r, const uint8_t s[32]);

void ge_ext_to_proj(ge_p2 r, const ge_p3 p);

void ge_ext_to_proj_niels(ge_cached r, const ge_p3 p);

void ge_ext_add(ge_p1p1 r, const ge_p3 p, const ge_cached q);

void ge_ext_sub(ge_p1p1 r, const ge_p3 p, const ge_cached q);

void ge_ext_madd(ge_p1p1 r, const ge_p3 p, const ge_precomp q);

void ge_ext_msub(ge_p1p1 r, const ge_p3 p, const ge_precomp q);

void ge_ext_dbl(ge_p1p1 r, const ge_p3 p);

void ge_proj_dbl(ge_p1p1 r, const ge_p2 p);

void ge_comp_to_proj(ge_p2 r, const ge_p1p1 p);

void ge_comp_to_ext(ge_p3 r, const ge_p1p1 p);

void ge_comp_to_proj_niels(ge_cached r, const ge_p1p1 p);

void ge_scalar_mul_base(ge_p3 r, const uint8_t a[32]);

void ge_scalar_mul(ge_p3 r, const uint8_t scalar[32], const ge_p3 q);

void ge_scalar_mul_add(uint8_t *s, const uint8_t *a, const uint8_t *b, const uint8_t *c);

void ge_scalar_reduce(uint8_t s[64]);

void ge_double_scalar_mul_vartime(ge_p2 r, const uint8_t *a, const ge_p3 A, const uint8_t *b);

#endif //O1C_CURVE25519_H
