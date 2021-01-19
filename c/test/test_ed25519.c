#include <sodium.h>

#include "o1c.h"
#include "test_util.h"

static inline void init_buf(uint8_t *const buf, const size_t len) {
    for (size_t i = 0; i < len; ++i) buf[i] = i % UINT8_MAX;
}

int main() {
    uint8_t private_key[o1c_sign_KEY_BYTES], public_key[o1c_sign_KEY_BYTES], signature[o1c_sign_BYTES], pt[1024];
    uint8_t expanded_key[o1c_sign_KEYPAIR_BYTES];
    init_buf(private_key, sizeof private_key);
    init_buf(pt, sizeof pt);

    o1c_sign_seed_keypair(public_key, expanded_key, private_key);
    uint8_t expected_sk[o1c_sign_KEYPAIR_BYTES], expected_pk[o1c_sign_KEY_BYTES];
    assert(crypto_sign_ed25519_seed_keypair(expected_pk, expected_sk, private_key) != -1);
    assert_eq(expected_pk, public_key, o1c_sign_KEY_BYTES);
    assert_eq(expected_sk, expanded_key, o1c_sign_KEYPAIR_BYTES);

    for (size_t len = 0; len < sizeof pt; ++len) {
        o1c_sign_detached(signature, pt, len, expanded_key);
        assert(o1c_sign_verify_detached(signature, pt, len, public_key));
        assert(crypto_sign_ed25519_verify_detached(signature, pt, len, public_key) != -1);
    }
}
