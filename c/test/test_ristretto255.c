#include <assert.h>
#include <sodium.h>

#include "o1c.h"
#include "test_util.h"

void test_base_mul(void) {
    o1c_scalar_t sk;
    o1c_scalar_random(sk);
    o1c_po_group_element_t pk;
    uint8_t expected[o1c_po_group_element_BYTES];
    assert(o1c_po_group_scalar_mul_base(pk, sk));
    assert(crypto_scalarmult_ristretto255_base(expected, sk->v) != -1);
    assert_eq(expected, pk->v, o1c_po_group_element_BYTES);
}

void test_scalar_mul(void) {
    o1c_scalar_t skA, skB;
    o1c_po_group_element_t pkA, pkB;
    o1c_po_group_keypair(pkA, skA);
    o1c_po_group_keypair(pkB, skB);
    o1c_po_group_element_t ssAB, ssBA;
    assert(o1c_po_group_scalar_mul(ssAB, skA, pkB));
    assert(o1c_po_group_scalar_mul(ssBA, skB, pkA));
    assert_eq(ssAB->v, ssBA->v, o1c_po_group_element_BYTES);
}

void test_elligator_map(void) {
    uint8_t h[o1c_po_group_element_HASH_BYTES];
    drbg_randombytes(h, o1c_po_group_element_HASH_BYTES);
    o1c_po_group_element_t actual;
    o1c_po_group_element_from_hash(actual, h);
    uint8_t expected[crypto_core_ristretto255_BYTES];
    crypto_core_ristretto255_from_hash(expected, h);
    assert_eq(expected, actual->v, crypto_core_ristretto255_BYTES);
}

// https://ristretto.group/test_vectors/ristretto255.html
void test_hash_to_point(void) {
    char *labels[] = {
            "Ristretto is traditionally a short shot of espresso coffee",
            "made with the normal amount of ground coffee but extracted with",
            "about half the amount of water in the same amount of time",
            "by using a finer grind.",
            "This produces a concentrated shot of coffee per volume.",
            "Just pulling a normal shot short will produce a weaker shot",
            "and is not a Ristretto as some believe.",
    };
    char *encoded_hash_to_points[] = {
            "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46",
            "f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b",
            "006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826",
            "f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a",
            "ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179",
            "e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628",
            "80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065",
    };
    uint8_t hash[o1c_po_group_element_HASH_BYTES];
    o1c_po_group_element_t point;
    uint8_t expected[o1c_po_group_element_BYTES];
    uint8_t input[64];
    for (int i = 0; i < 7; ++i) {
        size_t len = strlen(labels[i]);
        memcpy(input, labels[i], len);
        crypto_hash_sha512(hash, input, len);
        o1c_po_group_element_from_hash(point, hash);
        o1c_hex2bin(expected, o1c_po_group_element_BYTES, encoded_hash_to_points[i], 64);
        assert_eq(expected, point->v, o1c_po_group_element_BYTES);
    }
}

int main() {
    for (int i = 0; i < 1024; ++i) test_base_mul();
    for (int i = 0; i < 1024; ++i) test_scalar_mul();
    for (int i = 0; i < 1024; ++i) test_elligator_map();
    test_hash_to_point();
}
