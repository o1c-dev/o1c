#include "o1c.h"
#include "test.h"

typedef struct {
    size_t bytes;
    char seed[o1c_sign_KEY_BYTES * 2 + 1];
    char expanded_key[o1c_sign_KEYPAIR_BYTES * 2 + 1];
    char public_key[o1c_sign_KEY_BYTES * 2 + 1];
    char sig[o1c_sign_BYTES * 2 + 1];
} o1c_test_vector;

void run_checks(const o1c_test_vector *test) {
    uint8_t seed[o1c_sign_KEY_BYTES], expanded_key[o1c_sign_KEYPAIR_BYTES], public_key[o1c_sign_KEY_BYTES];
    uint8_t sig[o1c_sign_BYTES];
    uint8_t msg[test->bytes];
    init_buf(msg, sizeof msg);
    o1c_hex2bin(seed, o1c_sign_KEY_BYTES, test->seed, o1c_sign_KEY_BYTES * 2);
    o1c_hex2bin(expanded_key, o1c_sign_KEYPAIR_BYTES, test->expanded_key, o1c_sign_KEYPAIR_BYTES * 2);
    o1c_hex2bin(public_key, o1c_sign_KEY_BYTES, test->public_key, o1c_sign_KEY_BYTES * 2);
    o1c_hex2bin(sig, o1c_sign_BYTES, test->sig, o1c_sign_BYTES * 2);
    uint8_t actual_sk[o1c_sign_KEYPAIR_BYTES], actual_pk[o1c_sign_KEY_BYTES];
    o1c_sign_seed_keypair(actual_pk, actual_sk, seed);
    assert(o1c_mem_eq(expanded_key, actual_sk, sizeof actual_sk));
    assert(o1c_mem_eq(public_key, actual_pk, sizeof actual_pk));
    uint8_t actual_sig[o1c_sign_BYTES];
    o1c_sign_detached(actual_sig, msg, sizeof msg, expanded_key);
    assert(o1c_mem_eq(sig, actual_sig, sizeof actual_sig));
    assert(o1c_sign_verify_detached(sig, msg, sizeof msg, public_key));
}

#include "test_ed25519.h.inc"

int main() {
    for (size_t i = 0; i <= 256; ++i) run_checks(&data[i]);
}
