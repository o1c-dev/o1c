#include "scalar25519.h"
#include "util.h"
#include "test.h"

typedef struct {
    char a[o1c_scalar25519_BYTES * 2 + 1];
    char b[o1c_scalar25519_BYTES * 2 + 1];
    char c[o1c_scalar25519_BYTES * 2 + 1];
    char neg_a[o1c_scalar25519_BYTES * 2 + 1];
    char neg_b[o1c_scalar25519_BYTES * 2 + 1];
    char ab_c_prod_sum[o1c_scalar25519_BYTES * 2 + 1];
    char ab_c_prod_diff[o1c_scalar25519_BYTES * 2 + 1];
    char nonreduced[o1c_scalar25519_NONREDUCED_BYTES * 2 + 1];
    char reduced[o1c_scalar25519_BYTES * 2 + 1];
} o1c_test_vector;

#define assert_eq(a,b) assert(o1c_mem_eq((a)->v,(b)->v,o1c_scalar25519_BYTES))

void run_checks(const o1c_test_vector *test) {
    o1c_scalar25519_t a, b, c, d, neg_a, neg_b, ab_c_prod_sum, ab_c_prod_diff, reduced;
    uint8_t nonreduced[o1c_scalar25519_NONREDUCED_BYTES];
    o1c_hex2bin(a->v, o1c_scalar25519_BYTES, test->a, o1c_scalar25519_BYTES * 2);
    o1c_hex2bin(b->v, o1c_scalar25519_BYTES, test->b, o1c_scalar25519_BYTES * 2);
    o1c_hex2bin(c->v, o1c_scalar25519_BYTES, test->c, o1c_scalar25519_BYTES * 2);
    o1c_hex2bin(neg_a->v, o1c_scalar25519_BYTES, test->neg_a, o1c_scalar25519_BYTES * 2);
    o1c_hex2bin(neg_b->v, o1c_scalar25519_BYTES, test->neg_b, o1c_scalar25519_BYTES * 2);
    o1c_hex2bin(ab_c_prod_sum->v, o1c_scalar25519_BYTES, test->ab_c_prod_sum, o1c_scalar25519_BYTES * 2);
    o1c_hex2bin(ab_c_prod_diff->v, o1c_scalar25519_BYTES, test->ab_c_prod_diff, o1c_scalar25519_BYTES * 2);
    o1c_hex2bin(nonreduced, o1c_scalar25519_NONREDUCED_BYTES, test->nonreduced, o1c_scalar25519_NONREDUCED_BYTES * 2);
    o1c_hex2bin(reduced->v, o1c_scalar25519_BYTES, test->reduced, o1c_scalar25519_BYTES * 2);

#ifdef TODO_SIGNCRYPT
    o1c_scalar25519_negate(d, a);
    assert_eq(d, neg_a);

    o1c_scalar25519_negate(d, b);
    assert_eq(d, neg_b);

    o1c_scalar25519_negate(d, c);
    o1c_scalar25519_mul_add(d, a, b, d);
    assert_eq(d, ab_c_prod_diff);
#endif

    o1c_scalar25519_mul_add(d, a, b, c);
    assert_eq(d, ab_c_prod_sum);

    o1c_scalar25519_reduce(d, nonreduced);
    assert_eq(d, reduced);
}

#include "test_scalar25519.txt"

int main(void) {
    for (size_t i = 0; i <= 256; ++i) run_checks(&data[i]);
}
