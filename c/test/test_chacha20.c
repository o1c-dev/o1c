/* See COPYRIGHT for details
 * SPDX-License-Identifier: MIT OR Apache-2.0 OR BSD-1-Clause
 */

#include <stdbool.h>
#include <assert.h>

#include <sodium.h>

#include "o1c.h"

bool test_stream(const uint8_t k[o1c_crypto_KEY_BYTES], const uint8_t n[o1c_crypto_NONCE_BYTES], const size_t len) {
    uint8_t expected[len], actual[len];
    o1c_crypto_stream(actual, len, n, k);
    assert(crypto_stream_chacha20_ietf(expected, len, n, k) == 0);
    return sodium_memcmp(expected, actual, len);
}

bool test_xor(const uint8_t k[o1c_crypto_KEY_BYTES], const uint8_t n[o1c_crypto_NONCE_BYTES], const size_t len) {
    uint8_t expected[len], actual[len], input[len];
    for (size_t i = 0; i < len; ++i) input[i] = i % UINT8_MAX;
    o1c_crypto_xor(actual, input, len, n, k);
    assert(crypto_stream_chacha20_ietf_xor(expected, input, len, n, k) == 0);
    if (sodium_memcmp(expected, actual, len)) return true;

    o1c_crypto_xor(actual, expected, len, n, k);
    return sodium_memcmp(input, actual, len);
}

int main() {
    assert(sodium_init() == 0);
    uint8_t k[o1c_crypto_KEY_BYTES], n[o1c_crypto_NONCE_BYTES];
    for (size_t i = 0; i < sizeof(k); ++i) k[i] = i;
    for (size_t i = 0; i < sizeof(n); ++i) n[i] = i;

    bool failure = false;

    for (size_t len = 1; len < 1024; ++len) {
        if (test_stream(k, n, len)) failure = true;
        if (test_xor(k, n, len)) failure = true;
    }

    return failure ? EXIT_FAILURE : EXIT_SUCCESS;
}
