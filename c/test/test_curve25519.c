#include <assert.h>
#include <sodium.h>

#include "o1c.h"
#include "test_util.h"

int main() {
    uint8_t sk[o1c_scalar_BYTES];
    uint8_t pk[o1c_field_BYTES];
    drbg_randombytes(sk, o1c_scalar_BYTES);
    o1c_field_scalar_mul_base(pk, sk);

    uint8_t expected_pk[o1c_field_BYTES];
    assert(crypto_scalarmult_curve25519_base(expected_pk, sk) == 0);
    assert_eq(expected_pk, pk, o1c_field_BYTES);

    uint8_t ss[o1c_field_BYTES];
    uint8_t peer_pk[o1c_field_BYTES];
    drbg_randombytes(peer_pk, o1c_field_BYTES);

    if (!o1c_field_scalar_mul(ss, sk, peer_pk)) {
        char ax[65], bx[65], cx[65];
        fprintf(stderr, "ss = %s, sk = %s, pk = %s\n", o1c_bin2hex(ax, ss, 32), o1c_bin2hex(bx, sk, 32),
                o1c_bin2hex(cx, peer_pk, 32));
        return EXIT_FAILURE;
    }

    uint8_t expected_ss[o1c_field_BYTES];
    assert(crypto_scalarmult_curve25519(expected_ss, sk, peer_pk) == 0);
    assert_eq(expected_ss, ss, o1c_field_BYTES);

}
