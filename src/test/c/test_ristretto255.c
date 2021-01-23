#include "ristretto255.h"
#include "util.h"
#include "test.h"

typedef struct {
    char scalar[o1c_ristretto255_SCALAR_BYTES * 2 + 1];
    char element[o1c_ristretto255_ELEMENT_BYTES * 2 + 1];
    char hash[o1c_ristretto255_HASH_BYTES * 2 + 1];
    char point[o1c_ristretto255_ELEMENT_BYTES * 2 + 1];
    char product[o1c_ristretto255_ELEMENT_BYTES * 2 + 1];
} o1c_test_vector;

void run_checks(const o1c_test_vector *test) {
    o1c_ristretto255_scalar_t scalar;
    o1c_ristretto255_element_t element, point, product, actual;
    uint8_t hash[o1c_ristretto255_HASH_BYTES];
    o1c_hex2bin(scalar->v, o1c_ristretto255_SCALAR_BYTES, test->scalar, o1c_ristretto255_SCALAR_BYTES * 2);
    o1c_hex2bin(element->v, o1c_ristretto255_ELEMENT_BYTES, test->element, o1c_ristretto255_ELEMENT_BYTES * 2);
    o1c_hex2bin(hash, o1c_ristretto255_HASH_BYTES, test->hash, o1c_ristretto255_HASH_BYTES * 2);
    o1c_hex2bin(point->v, o1c_ristretto255_ELEMENT_BYTES, test->point, o1c_ristretto255_ELEMENT_BYTES * 2);
    o1c_hex2bin(product->v, o1c_ristretto255_ELEMENT_BYTES, test->product, o1c_ristretto255_ELEMENT_BYTES * 2);
    assert(o1c_ristretto255_scalar_mul_base(actual, scalar));
    assert(o1c_mem_eq(element->v, actual->v, o1c_ristretto255_ELEMENT_BYTES));
    o1c_ristretto255_from_hash(actual, hash);
    assert(o1c_mem_eq(point->v, actual->v, o1c_ristretto255_ELEMENT_BYTES));
    assert(o1c_ristretto255_scalar_mul(actual, scalar, point));
    assert(o1c_mem_eq(product->v, actual->v, o1c_ristretto255_ELEMENT_BYTES));
}

#include "test_ristretto255.txt"

int main(void) {
    for (size_t i = 0; i <= 256; ++i) run_checks(&data[i]);
}
