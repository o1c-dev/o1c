#include "o1c.h"
#include "test.h"

typedef struct {
    size_t bytes;
    char key[o1c_crypto_KEY_BYTES * 2 + 1];
    char nonce[o1c_crypto_NONCE_BYTES * 2 + 1];
    char *keystream;
    char *ciphertext;
} o1c_test_vector;

void run_checks(const o1c_test_vector *test) {
    uint8_t key[o1c_crypto_KEY_BYTES], nonce[o1c_crypto_NONCE_BYTES];
    uint8_t keystream[test->bytes], ciphertext[test->bytes];
    o1c_hex2bin(key, o1c_crypto_KEY_BYTES, test->key, o1c_crypto_KEY_BYTES * 2);
    o1c_hex2bin(nonce, o1c_crypto_NONCE_BYTES, test->nonce, o1c_crypto_NONCE_BYTES * 2);
    o1c_hex2bin(keystream, test->bytes, test->keystream, test->bytes * 2);
    o1c_hex2bin(ciphertext, test->bytes, test->ciphertext, test->bytes * 2);
    uint8_t actual[test->bytes];
    o1c_crypto_stream(actual, test->bytes, nonce, key);
    assert(o1c_mem_eq(keystream, actual, test->bytes));
    uint8_t plaintext[test->bytes];
    init_buf(plaintext, test->bytes);
    o1c_crypto_xor(actual, plaintext, test->bytes, nonce, key);
    assert(o1c_mem_eq(ciphertext, actual, test->bytes));
}

#include "test_chacha20.h.inc"

int main() {
    for (size_t i = 0; i < 256; ++i) run_checks(&data[i]);
}
