#include "o1c.h"
#include "test.h"

typedef struct {
    size_t ad_len;
    size_t pt_len;
    char key[o1c_aead_KEY_BYTES * 2 + 1];
    char nonce[o1c_aead_NONCE_BYTES * 2 + 1];
    char *ciphertext;
} o1c_test_vector;

void run_checks(const o1c_test_vector *test) {
    uint8_t key[o1c_aead_KEY_BYTES], nonce[o1c_aead_NONCE_BYTES];
    uint8_t ad[test->ad_len], pt[test->pt_len];
    init_buf(ad, sizeof ad);
    init_buf(pt, sizeof pt);
    uint8_t ct[test->pt_len + o1c_aead_TAG_BYTES];
    o1c_hex2bin(key, o1c_aead_KEY_BYTES, test->key, o1c_aead_KEY_BYTES * 2);
    o1c_hex2bin(nonce, o1c_aead_NONCE_BYTES, test->nonce, o1c_aead_NONCE_BYTES * 2);
    o1c_hex2bin(ct, sizeof ct, test->ciphertext, (test->pt_len + o1c_aead_TAG_BYTES) * 2 + 1);
    uint8_t actual[test->pt_len + o1c_aead_TAG_BYTES];
    o1c_aead_encrypt(actual, actual + sizeof pt, pt, sizeof pt, ad, sizeof ad, nonce, key);
    assert(o1c_mem_eq(ct, actual, sizeof actual));
}

#include "test_xchacha20poly1305.txt"

int main() {
    for (size_t i = 0; i <= 32*32; ++i) run_checks(&data[i]);
}
