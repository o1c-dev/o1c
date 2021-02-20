#include "ristretto255.h"
#include "drbg.h"

#include <assert.h>

void smoke_test(void) {
    uint8_t sk[o1c_ristretto255_KEY_BYTES], pk[o1c_ristretto255_BYTES];
    drbg_randombytes(sk, o1c_ristretto255_KEY_BYTES);
    o1c_ristretto255b3_derive_pubkey(pk, sk);
    uint8_t msg[2043];
    drbg_randombytes(msg, sizeof msg);
    uint8_t sig[o1c_ristretto255_SIGN_BYTES];
    o1c_ristretto255b3_sign(sig, msg, sizeof msg, sk);
    assert(o1c_ristretto255b3_verify(sig, msg, sizeof msg, pk));
}

int main(void) {
    smoke_test();
}
