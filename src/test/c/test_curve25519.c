#include "x25519.h"
#include "util.h"
#include "test.h"

typedef struct {
    char sa[o1c_x25519_SCALAR_BYTES * 2 + 1];
    char sb[o1c_x25519_SCALAR_BYTES * 2 + 1];
    char ea[o1c_x25519_ELEMENT_BYTES * 2 + 1];
    char eb[o1c_x25519_ELEMENT_BYTES * 2 + 1];
    char product[o1c_x25519_ELEMENT_BYTES * 2 + 1];
} o1c_test_vector;

void run_checks(const o1c_test_vector *test) {
    o1c_x25519_scalar_t sa, sb;
    o1c_x25519_element_t ea, eb, product, result;
    o1c_hex2bin(sa->v, o1c_x25519_SCALAR_BYTES, test->sa, o1c_x25519_SCALAR_BYTES * 2);
    o1c_hex2bin(sb->v, o1c_x25519_SCALAR_BYTES, test->sb, o1c_x25519_SCALAR_BYTES * 2);
    o1c_hex2bin(ea->v, o1c_x25519_ELEMENT_BYTES, test->ea, o1c_x25519_ELEMENT_BYTES * 2);
    o1c_hex2bin(eb->v, o1c_x25519_ELEMENT_BYTES, test->eb, o1c_x25519_ELEMENT_BYTES * 2);
    o1c_hex2bin(product->v, o1c_x25519_ELEMENT_BYTES, test->product, o1c_x25519_ELEMENT_BYTES * 2);
    o1c_x25519_scalar_mul_base(result, sa);
    assert(o1c_mem_eq(ea->v, result->v, o1c_x25519_ELEMENT_BYTES));
    o1c_x25519_scalar_mul_base(result, sb);
    assert(o1c_mem_eq(eb->v, result->v, o1c_x25519_ELEMENT_BYTES));
    assert(o1c_x25519_scalar_mul(result, sa, eb));
    assert(o1c_mem_eq(product->v, result->v, o1c_x25519_ELEMENT_BYTES));
    assert(o1c_x25519_scalar_mul(result, sb, ea));
    assert(o1c_mem_eq(product->v, result->v, o1c_x25519_ELEMENT_BYTES));
}

void smoke_test(void) {
    o1c_x25519_scalar_t a, b;
    o1c_x25519_element_t A, B, AB, BA;
    o1c_x25519_keypair(A, a);
    o1c_x25519_keypair(B, b);
    assert(o1c_x25519_scalar_mul(AB, a, B));
    assert(o1c_x25519_scalar_mul(BA, b, A));
    assert(o1c_mem_eq(AB->v, BA->v, o1c_x25519_ELEMENT_BYTES));
}

#include "test_curve25519.txt"

int main(void) {
    smoke_test();
    for (size_t i = 0; i <= 256; ++i) run_checks(&data[i]);
}
