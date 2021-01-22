#include "ed25519.h"
#include "util.h"
#include "test.h"

typedef struct {
    size_t bytes;
    char seed[o1c_ed25519_SEED_BYTES * 2 + 1];
    char expanded_key[o1c_ed25519_EXPANDED_BYTES * 2 + 1];
    char public_key[o1c_ed25519_PUBLIC_BYTES * 2 + 1];
    char sig[o1c_ed25519_SIGN_BYTES * 2 + 1];
} o1c_test_vector;

void run_checks(const o1c_test_vector *test) {
    o1c_ed25519_seed_t seed;
    o1c_ed25519_expanded_key_t expanded_key, actual_expanded;
    o1c_ed25519_public_key_t public_key;
    uint8_t sig[o1c_ed25519_SIGN_BYTES];
    uint8_t msg[test->bytes];
    init_buf(msg, sizeof msg);
    o1c_hex2bin(seed->v, o1c_ed25519_SEED_BYTES, test->seed, o1c_ed25519_SEED_BYTES * 2);
    o1c_hex2bin(expanded_key->v, o1c_ed25519_EXPANDED_BYTES, test->expanded_key, o1c_ed25519_EXPANDED_BYTES * 2);
    o1c_hex2bin(public_key->v, o1c_ed25519_PUBLIC_BYTES, test->public_key, o1c_ed25519_PUBLIC_BYTES * 2);
    o1c_hex2bin(sig, o1c_ed25519_SIGN_BYTES, test->sig, o1c_ed25519_SIGN_BYTES * 2);
    o1c_ed25519_expand_key(actual_expanded, seed);
    assert(o1c_mem_eq(expanded_key->v, actual_expanded->v, o1c_ed25519_EXPANDED_BYTES));
    uint8_t actual_sig[o1c_ed25519_SIGN_BYTES];
    o1c_ed25519_sign(actual_sig, msg, sizeof msg, expanded_key);
    assert(o1c_mem_eq(sig, actual_sig, o1c_ed25519_SIGN_BYTES));
    assert(o1c_ed25519_verify(sig, msg, sizeof msg, public_key));
}

#include "test_ed25519.txt"

int main() {
    for (size_t i = 0; i <= 256; ++i) run_checks(&data[i]);
}
