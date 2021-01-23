#include "xchacha20poly1305.h"
#include "chacha20.h"
#include "poly1305.h"
#include "util.h"
#include "mem.h"

#include <string.h>
#include <stdbool.h>
#include <stdint.h>

static const uint8_t pad0[16] = {0};

static inline void
init_poly1305(o1c_poly1305_t ctx, const uint8_t *ad, const size_t ad_len, const uint8_t *n, const uint8_t *k) {
    uint8_t key[o1c_poly1305_KEY_BYTES];
    o1c_chacha20_stream(key, o1c_poly1305_KEY_BYTES, n, k);
    o1c_poly1305_key_setup(ctx, key);
    o1c_bzero(key, o1c_poly1305_KEY_BYTES);
    o1c_poly1305_update(ctx, ad, ad_len);
    o1c_poly1305_update(ctx, pad0, (0x10 - ad_len) & 0xf);
}

void
o1c_xchacha20poly1305_encrypt(uint8_t *c, uint8_t t[o1c_xchacha20poly1305_TAG_BYTES], const uint8_t *m,
                              size_t m_len, const uint8_t *ad, size_t ad_len,
                              const uint8_t n[o1c_xchacha20poly1305_NONCE_BYTES],
                              const uint8_t k[o1c_xchacha20poly1305_KEY_BYTES]) {
    uint8_t sk[o1c_chacha20_KEY_BYTES], sn[o1c_chacha20_NONCE_BYTES] = {0};
    o1c_hchacha20(sk, n, k);
    memcpy(sn + 4, n + 16, o1c_chacha20_NONCE_BYTES - 4);
    o1c_poly1305_t st;
    init_poly1305(st, ad, ad_len, sn, sk);

    o1c_chacha20_xor_ic(c, m, m_len, sn, 1U, sk);
    o1c_poly1305_update(st, c, m_len);
    o1c_poly1305_update(st, pad0, (0x10 - m_len) & 0xf);

    uint8_t len[8];
    store64_le(len, (uint64_t) ad_len);
    o1c_poly1305_update(st, len, sizeof len);
    store64_le(len, (uint64_t) m_len);
    o1c_poly1305_update(st, len, sizeof len);

    o1c_poly1305_final(st, t);
    o1c_bzero(st, sizeof st);
}

bool
o1c_xchacha20poly1305_decrypt(uint8_t *m, const uint8_t t[o1c_xchacha20poly1305_TAG_BYTES], const uint8_t *c,
                              size_t c_len, const uint8_t *ad, size_t ad_len,
                              const uint8_t n[o1c_xchacha20poly1305_NONCE_BYTES],
                              const uint8_t k[o1c_xchacha20poly1305_KEY_BYTES]) {
    uint8_t sk[o1c_chacha20_KEY_BYTES], sn[o1c_chacha20_NONCE_BYTES] = {0};
    o1c_hchacha20(sk, n, k);
    memcpy(sn + 4, n + 16, o1c_chacha20_NONCE_BYTES - 4);
    o1c_poly1305_t st;
    init_poly1305(st, ad, ad_len, sn, sk);

    o1c_poly1305_update(st, c, c_len);
    o1c_poly1305_update(st, pad0, (0x10 - c_len) & 0xf);

    uint8_t len[8];
    store64_le(len, (uint64_t) ad_len);
    o1c_poly1305_update(st, len, sizeof len);
    store64_le(len, (uint64_t) c_len);
    o1c_poly1305_update(st, len, sizeof len);

    uint8_t tag[o1c_xchacha20poly1305_TAG_BYTES];
    o1c_poly1305_final(st, tag);
    o1c_bzero(st, sizeof st);

    bool ret = o1c_mem_eq(t, tag, o1c_xchacha20poly1305_TAG_BYTES);
    if (m == NULL) {
        return ret;
    }
    if (!ret) {
        o1c_bzero(m, c_len);
        return false;
    }
    o1c_chacha20_xor_ic(m, c, c_len, sn, 1U, sk);
    return true;
}
