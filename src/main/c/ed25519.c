#include "ed25519.h"
#include "curve25519.h"
#include "scalar25519.h"
#include "sha512.h"
#include "drbg.h"

#include <string.h>

void o1c_ed25519_expand_key(o1c_ed25519_expanded_key_t private_key, const o1c_ed25519_seed_t seed) {
    uint8_t az[o1c_sha512_HASH_BYTES];
    o1c_sha512(az, seed->v, o1c_ed25519_SEED_BYTES);
    az[0] &= 248;
    az[31] &= 127;
    az[31] |= 64;
    ge_p3 A;
    o1c_scalar25519_t as;
    memcpy(as->v, az, 32);
    ge_scalar_mul_base(A, as);
    memcpy(private_key->v, seed->v, o1c_ed25519_SEED_BYTES);
    ge_ext_serialize(private_key->v + 32, A);
}

void o1c_ed25519_keypair(o1c_ed25519_public_key_t public_key, o1c_ed25519_expanded_key_t private_key) {
    o1c_ed25519_seed_t seed;
    drbg_randombytes(seed->v, o1c_ed25519_SEED_BYTES);
    o1c_ed25519_expand_key(private_key, seed);
    memcpy(public_key->v, private_key->v + 32, 32);
}

void o1c_ed25519_sign(uint8_t s[o1c_ed25519_SIGN_BYTES], const uint8_t *m, size_t len,
                      const o1c_ed25519_expanded_key_t key) {
    uint8_t az[o1c_sha512_HASH_BYTES];
    o1c_sha512(az, key->v, 32);
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    o1c_sha512_ctx_t ctx;
    o1c_sha512_init(ctx);
    o1c_sha512_update(ctx, az + 32, 32);
    o1c_sha512_update(ctx, m, len);
    uint8_t nonce[o1c_sha512_HASH_BYTES];
    o1c_sha512_final(ctx, nonce);
    o1c_scalar25519_t nonce_r;
    o1c_scalar25519_reduce(nonce_r, nonce);
    ge_p3 R;
    ge_scalar_mul_base(R, nonce_r);
    ge_ext_serialize(s, R);
    o1c_sha512_init(ctx);
    o1c_sha512_update(ctx, s, 32);
    o1c_sha512_update(ctx, key->v + 32, 32);
    o1c_sha512_update(ctx, m, len);
    uint8_t hram[o1c_sha512_HASH_BYTES];
    o1c_sha512_final(ctx, hram);
    o1c_scalar25519_t hram_r, result, az_r;
    o1c_scalar25519_reduce(hram_r, hram);
    memcpy(az_r->v, az, 32);
    o1c_scalar25519_mul_add(result, hram_r, az_r, nonce_r);
    memcpy(s + 32, result->v, 32);
}

bool o1c_ed25519_verify(const uint8_t s[o1c_ed25519_SIGN_BYTES], const uint8_t *m, size_t len,
                        const o1c_ed25519_public_key_t key) {
    ge_p3 A;
    if ((s[63] & 224) != 0 || !ge_ext_deserialize_vartime(A, key->v)) {
        return false;
    }
    fe t;
    fe_neg(t, A->X);
    fe_reduce(A->X, t);
    fe_neg(t, A->T);
    fe_reduce(A->T, t);
    uint8_t pk_copy[o1c_ed25519_PUBLIC_BYTES];
    memcpy(pk_copy, key->v, o1c_ed25519_PUBLIC_BYTES);
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
    o1c_sha512_ctx_t ctx;
    o1c_sha512_init(ctx);
    o1c_sha512_update(ctx, s, 32);
    o1c_sha512_update(ctx, key->v, 32);
    o1c_sha512_update(ctx, m, len);
    uint8_t hash[o1c_sha512_HASH_BYTES];
    o1c_sha512_final(ctx, hash);
    o1c_scalar25519_t h;
    o1c_scalar25519_reduce(h, hash);
    ge_p2 R;
    // TODO: remove need to cast here
    ge_double_scalar_mul_vartime(R, h, A, (const o1c_scalar25519_s *) s_copy.u8);
    uint8_t r_check[32];
    ge_proj_serialize(r_check, R);
    return o1c_mem_eq(r_check, r_copy, 32);
}
