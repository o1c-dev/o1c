#include "ristretto255.h"
#include "util.h"

typedef struct {
    char scalar[o1c_scalar25519_BYTES * 2 + 1];
    char element[o1c_ristretto255_BYTES * 2 + 1];
    char hash[o1c_ristretto255_HASH_BYTES * 2 + 1];
    char point[o1c_ristretto255_BYTES * 2 + 1];
    char product[o1c_ristretto255_BYTES * 2 + 1];
} o1c_test_vector;

void hex2ret(o1c_ristretto255_t r, const char *hex) {
    uint8_t serialized[o1c_ristretto255_BYTES];
    o1c_hex2bin(serialized, o1c_ristretto255_BYTES, hex, o1c_ristretto255_BYTES * 2);
    o1c_ristretto255_deserialize(r, serialized);
}

void run_checks(const o1c_test_vector *test) {
    o1c_scalar25519_t scalar;
    o1c_ristretto255_t element, point, product, actual;
    uint8_t hash[o1c_ristretto255_HASH_BYTES];
    o1c_hex2bin(scalar->v, o1c_scalar25519_BYTES, test->scalar, o1c_scalar25519_BYTES * 2);
    hex2ret(element, test->element);
    hex2ret(point, test->point);
    o1c_hex2bin(hash, o1c_ristretto255_HASH_BYTES, test->hash, o1c_ristretto255_HASH_BYTES * 2);
    hex2ret(product, test->product);
    assert(o1c_ristretto255_scalar_mul_base(actual, scalar));
    assert(o1c_ristretto255_equal(element, actual));
    o1c_ristretto255_from_hash(actual, hash);
    assert(o1c_ristretto255_equal(point, actual));
    assert(o1c_ristretto255_scalar_mul(actual, scalar, point));
    assert(o1c_ristretto255_equal(product, actual));
}

#include "test_ristretto255.txt"

int main(void) {
    for (size_t i = 0; i <= 256; ++i) run_checks(&data[i]);
}
