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

int main() {
    for (int i = 0; i < 1024; ++i) test_base_mul();
    for (int i = 0; i < 1024; ++i) test_scalar_mul();
}
