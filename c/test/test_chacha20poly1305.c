#include <stdlib.h>
#include <sodium.h>

#include "o1c.h"
#include "test_util.h"

static inline void init_buf(uint8_t *const buf, const size_t len) {
    for (size_t i = 0; i < len; ++i) buf[i] = i % UINT8_MAX;
}

int main() {
    uint8_t key[o1c_aead_KEY_BYTES], nonce[o1c_aead_NONCE_BYTES], tag[o1c_aead_TAG_BYTES];
    uint8_t pt[64], ct[64], ad[64], tmp[64];
    init_buf(key, sizeof key);
    init_buf(nonce, sizeof nonce);
    init_buf(pt, sizeof pt);
    init_buf(ad, sizeof ad);
    for (size_t m_len = 0; m_len <= 64; ++m_len) {
        for (size_t ad_len = 0; ad_len <= 64; ++ad_len) {
            o1c_aead_encrypt(ct, tag, pt, m_len, ad, ad_len, nonce, key);
            assert(o1c_aead_decrypt(tmp, tag, ct, m_len, ad, ad_len, nonce, key));
            assert_eq(pt, tmp, m_len);

            // compatibility tests
            assert(crypto_aead_xchacha20poly1305_ietf_decrypt_detached(tmp, NULL, ct, m_len, tag, ad, ad_len, nonce,
                                                                       key) != -1);
            assert_eq(pt, tmp, m_len);
        }
    }
}
