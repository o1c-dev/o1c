#include "o1c.h"
#include "test.h"

typedef struct {
    char sa[o1c_scalar_BYTES * 2 + 1];
    char sb[o1c_scalar_BYTES * 2 + 1];
    char ea[o1c_field_BYTES * 2 + 1];
    char eb[o1c_field_BYTES * 2 + 1];
    char product[o1c_field_BYTES * 2 + 1];
} o1c_test_vector;

void run_checks(const o1c_test_vector *test) {
    uint8_t sa[o1c_scalar_BYTES], sb[o1c_scalar_BYTES], ea[o1c_field_BYTES], eb[o1c_field_BYTES];
    uint8_t product[o1c_field_BYTES];
    o1c_hex2bin(sa, o1c_scalar_BYTES, test->sa, o1c_scalar_BYTES * 2);
    o1c_hex2bin(sb, o1c_scalar_BYTES, test->sb, o1c_scalar_BYTES * 2);
    o1c_hex2bin(ea, o1c_field_BYTES, test->ea, o1c_field_BYTES * 2);
    o1c_hex2bin(eb, o1c_field_BYTES, test->eb, o1c_field_BYTES * 2);
    o1c_hex2bin(product, o1c_field_BYTES, test->product, o1c_field_BYTES * 2);
    uint8_t result[o1c_field_BYTES];
    o1c_field_scalar_mul_base(result, sa);
    assert(o1c_mem_eq(ea, result, sizeof result));
    o1c_field_scalar_mul_base(result, sb);
    assert(o1c_mem_eq(eb, result, sizeof result));
    o1c_field_scalar_mul(result, sa, eb);
    assert(o1c_mem_eq(product, result, sizeof result));
    o1c_field_scalar_mul(result, sb, ea);
    assert(o1c_mem_eq(product, result, sizeof result));
}

#include "test_curve25519.txt"

int main(void) {
    for (size_t i = 0; i <= 256; ++i) run_checks(&data[i]);
}
