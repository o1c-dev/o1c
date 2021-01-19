#include "o1c.h"
#include "mem.h"

static const uint8_t pad0[16] = {0};

#define U32V(v) ((uint32_t)(v) & UINT32_C(0xFFFFFFFF))

#define QUARTERROUND(a, b, c, d) \
  a = U32V((a)+(b)); d = rotl32((d)^(a),16); \
  c = U32V((c)+(d)); b = rotl32((b)^(c),12); \
  a = U32V((a)+(b)); d = rotl32((d)^(a), 8); \
  c = U32V((c)+(d)); b = rotl32((b)^(c), 7);

static inline void
init_auth(o1c_auth_t st, const uint8_t *ad, unsigned long long int ad_len, const uint8_t *n, const uint8_t *k) {
    uint8_t poly_key[o1c_auth_KEY_BYTES];
    o1c_crypto_stream(poly_key, o1c_auth_KEY_BYTES, n, k);
    o1c_auth_key_setup(st, poly_key);
    o1c_bzero(poly_key, o1c_auth_KEY_BYTES);

    o1c_auth_update(st, ad, ad_len);
    o1c_auth_update(st, pad0, (0x10 - ad_len) & 0xf);
}

static void
hchacha(uint8_t *sk, const uint8_t *n, const uint8_t *k) {
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

void
o1c_aead_encrypt(uint8_t *c, uint8_t t[o1c_aead_TAG_BYTES], const uint8_t *m, unsigned long m_len, const uint8_t *ad,
                 unsigned long ad_len, const uint8_t n[o1c_aead_NONCE_BYTES], const uint8_t k[o1c_aead_KEY_BYTES]) {
    uint8_t sk[o1c_crypto_KEY_BYTES], sn[o1c_crypto_NONCE_BYTES] = {0};
    hchacha(sk, n, k);
    memcpy(sn + 4, n + 16, o1c_crypto_NONCE_BYTES - 4);
    o1c_auth_t st;
    init_auth(st, ad, ad_len, sn, sk);

    o1c_crypto_xor_ic(c, m, m_len, sn, 1U, sk);
    o1c_auth_update(st, c, m_len);
    o1c_auth_update(st, pad0, (0x10 - m_len) & 0xf);

    uint8_t len[8];
    store64_le(len, (uint64_t) ad_len);
    o1c_auth_update(st, len, sizeof len);
    store64_le(len, (uint64_t) m_len);
    o1c_auth_update(st, len, sizeof len);

    o1c_auth_final(st, t);
    o1c_bzero(st, sizeof st);
}

bool
o1c_aead_decrypt(uint8_t *m, const uint8_t t[o1c_aead_TAG_BYTES], const uint8_t *c, unsigned long c_len,
                 const uint8_t *ad, unsigned long ad_len, const uint8_t n[o1c_aead_NONCE_BYTES],
                 const uint8_t k[o1c_aead_KEY_BYTES]) {
    uint8_t sk[o1c_crypto_KEY_BYTES], sn[o1c_crypto_NONCE_BYTES] = {0};
    hchacha(sk, n, k);
    memcpy(sn + 4, n + 16, o1c_crypto_NONCE_BYTES - 4);
    o1c_auth_t st;
    init_auth(st, ad, ad_len, sn, sk);

    o1c_auth_update(st, c, c_len);
    o1c_auth_update(st, pad0, (0x10 - c_len) & 0xf);

    uint8_t len[8];
    store64_le(len, (uint64_t) ad_len);
    o1c_auth_update(st, len, sizeof len);
    store64_le(len, (uint64_t) c_len);
    o1c_auth_update(st, len, sizeof len);

    uint8_t tag[o1c_aead_TAG_BYTES];
    o1c_auth_final(st, tag);
    o1c_bzero(st, sizeof st);

    bool ret = o1c_mem_eq(t, tag, o1c_aead_TAG_BYTES);
    if (m == NULL) {
        return ret;
    }
    if (!ret) {
        o1c_bzero(m, c_len);
        return false;
    }
    o1c_crypto_xor_ic(m, c, c_len, sn, 1U, sk);
    return true;
}
