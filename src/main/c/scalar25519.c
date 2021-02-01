#include "scalar25519.h"
#include "drbg.h"
#include "util.h"

#include <stdint.h>
#include <string.h>

/* 2^252+27742317777372353535851937790883648493 */
static const uint8_t L[] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
        0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

// int64_lshift21 returns |a << 21| but is defined when shifting bits into the
// sign bit. This works around a language flaw in C.
static inline int64_t int64_lshift21(int64_t a) {
    return (int64_t) ((uint64_t) a << 21);
}

static inline uint64_t load_3(const uint8_t *in) {
    uint64_t result;
    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;
    return result;
}

static inline uint64_t load_4(const uint8_t *in) {
    uint64_t result;
    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;
    result |= ((uint64_t) in[3]) << 24;
    return result;
}

bool o1c_scalar25519_is_canonical(const o1c_scalar25519_t s) {
    uint8_t c = 0;
    uint8_t n = 1;
    unsigned int i = 32;

    do {
        i--;
        c |= ((s->v[i] - L[i]) >> 8) & n;
        n &= ((s->v[i] ^ L[i]) - 1) >> 8;
    } while (i != 0);

    return (c != 0);
}

void o1c_scalar25519_random(o1c_scalar25519_t s) {
    do {
        drbg_randombytes(s->v, o1c_scalar25519_BYTES);
        s->v[o1c_scalar25519_BYTES - 1] &= 0x1f;
    } while (!o1c_scalar25519_is_canonical(s) || o1c_is_zero(s->v, o1c_scalar25519_BYTES));
}

void o1c_scalar25519_reduce(o1c_scalar25519_t s, const uint8_t n[o1c_scalar25519_NONREDUCED_BYTES]) {
    int64_t s0 = 2097151 & load_3(n);
    int64_t s1 = 2097151 & (load_4(n + 2) >> 5);
    int64_t s2 = 2097151 & (load_3(n + 5) >> 2);
    int64_t s3 = 2097151 & (load_4(n + 7) >> 7);
    int64_t s4 = 2097151 & (load_4(n + 10) >> 4);
    int64_t s5 = 2097151 & (load_3(n + 13) >> 1);
    int64_t s6 = 2097151 & (load_4(n + 15) >> 6);
    int64_t s7 = 2097151 & (load_3(n + 18) >> 3);
    int64_t s8 = 2097151 & load_3(n + 21);
    int64_t s9 = 2097151 & (load_4(n + 23) >> 5);
    int64_t s10 = 2097151 & (load_3(n + 26) >> 2);
    int64_t s11 = 2097151 & (load_4(n + 28) >> 7);
    int64_t s12 = 2097151 & (load_4(n + 31) >> 4);
    int64_t s13 = 2097151 & (load_3(n + 34) >> 1);
    int64_t s14 = 2097151 & (load_4(n + 36) >> 6);
    int64_t s15 = 2097151 & (load_3(n + 39) >> 3);
    int64_t s16 = 2097151 & load_3(n + 42);
    int64_t s17 = 2097151 & (load_4(n + 44) >> 5);
    int64_t s18 = 2097151 & (load_3(n + 47) >> 2);
    int64_t s19 = 2097151 & (load_4(n + 49) >> 7);
    int64_t s20 = 2097151 & (load_4(n + 52) >> 4);
    int64_t s21 = 2097151 & (load_3(n + 55) >> 1);
    int64_t s22 = 2097151 & (load_4(n + 57) >> 6);
    int64_t s23 = (load_4(n + 60) >> 3);
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;
    int64_t carry10;
    int64_t carry11;
    int64_t carry12;
    int64_t carry13;
    int64_t carry14;
    int64_t carry15;
    int64_t carry16;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    s22 = 0;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    s21 = 0;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    s20 = 0;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    s19 = 0;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    s18 = 0;

    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= int64_lshift21(carry12);
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= int64_lshift21(carry14);
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= int64_lshift21(carry16);

    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= int64_lshift21(carry13);
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= int64_lshift21(carry15);

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    s17 = 0;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    s16 = 0;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    s15 = 0;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    s14 = 0;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    s13 = 0;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);

    s->v[0] = s0 >> 0;
    s->v[1] = s0 >> 8;
    s->v[2] = (s0 >> 16) | (s1 << 5);
    s->v[3] = s1 >> 3;
    s->v[4] = s1 >> 11;
    s->v[5] = (s1 >> 19) | (s2 << 2);
    s->v[6] = s2 >> 6;
    s->v[7] = (s2 >> 14) | (s3 << 7);
    s->v[8] = s3 >> 1;
    s->v[9] = s3 >> 9;
    s->v[10] = (s3 >> 17) | (s4 << 4);
    s->v[11] = s4 >> 4;
    s->v[12] = s4 >> 12;
    s->v[13] = (s4 >> 20) | (s5 << 1);
    s->v[14] = s5 >> 7;
    s->v[15] = (s5 >> 15) | (s6 << 6);
    s->v[16] = s6 >> 2;
    s->v[17] = s6 >> 10;
    s->v[18] = (s6 >> 18) | (s7 << 3);
    s->v[19] = s7 >> 5;
    s->v[20] = s7 >> 13;
    s->v[21] = s8 >> 0;
    s->v[22] = s8 >> 8;
    s->v[23] = (s8 >> 16) | (s9 << 5);
    s->v[24] = s9 >> 3;
    s->v[25] = s9 >> 11;
    s->v[26] = (s9 >> 19) | (s10 << 2);
    s->v[27] = s10 >> 6;
    s->v[28] = (s10 >> 14) | (s11 << 7);
    s->v[29] = s11 >> 1;
    s->v[30] = s11 >> 9;
    s->v[31] = s11 >> 17;
}

void o1c_scalar25519_clamp(o1c_scalar25519_t s, const uint8_t n[o1c_scalar25519_BYTES]) {
    memcpy(s->v, n, o1c_scalar25519_BYTES);
    s->v[0] &= 248;
    // note that BoringSSL clamps this more strictly by using 63 instead of 127 in its ed25519 code
    s->v[31] &= 127;
    s->v[31] |= 64;
}

void o1c_scalar25519_deserialize(o1c_scalar25519_t s, const uint8_t n[o1c_scalar25519_BYTES]) {
    memcpy(s->v, n, o1c_scalar25519_BYTES);
    s->v[31] &= 127;
}

void o1c_scalar25519_mul_add(o1c_scalar25519_t s, const o1c_scalar25519_t a, const o1c_scalar25519_t b,
                             const o1c_scalar25519_t c) {
    int64_t a0 = 2097151 & load_3(a->v);
    int64_t a1 = 2097151 & (load_4(a->v + 2) >> 5);
    int64_t a2 = 2097151 & (load_3(a->v + 5) >> 2);
    int64_t a3 = 2097151 & (load_4(a->v + 7) >> 7);
    int64_t a4 = 2097151 & (load_4(a->v + 10) >> 4);
    int64_t a5 = 2097151 & (load_3(a->v + 13) >> 1);
    int64_t a6 = 2097151 & (load_4(a->v + 15) >> 6);
    int64_t a7 = 2097151 & (load_3(a->v + 18) >> 3);
    int64_t a8 = 2097151 & load_3(a->v + 21);
    int64_t a9 = 2097151 & (load_4(a->v + 23) >> 5);
    int64_t a10 = 2097151 & (load_3(a->v + 26) >> 2);
    int64_t a11 = (load_4(a->v + 28) >> 7);
    int64_t b0 = 2097151 & load_3(b->v);
    int64_t b1 = 2097151 & (load_4(b->v + 2) >> 5);
    int64_t b2 = 2097151 & (load_3(b->v + 5) >> 2);
    int64_t b3 = 2097151 & (load_4(b->v + 7) >> 7);
    int64_t b4 = 2097151 & (load_4(b->v + 10) >> 4);
    int64_t b5 = 2097151 & (load_3(b->v + 13) >> 1);
    int64_t b6 = 2097151 & (load_4(b->v + 15) >> 6);
    int64_t b7 = 2097151 & (load_3(b->v + 18) >> 3);
    int64_t b8 = 2097151 & load_3(b->v + 21);
    int64_t b9 = 2097151 & (load_4(b->v + 23) >> 5);
    int64_t b10 = 2097151 & (load_3(b->v + 26) >> 2);
    int64_t b11 = (load_4(b->v + 28) >> 7);
    int64_t c0 = 2097151 & load_3(c->v);
    int64_t c1 = 2097151 & (load_4(c->v + 2) >> 5);
    int64_t c2 = 2097151 & (load_3(c->v + 5) >> 2);
    int64_t c3 = 2097151 & (load_4(c->v + 7) >> 7);
    int64_t c4 = 2097151 & (load_4(c->v + 10) >> 4);
    int64_t c5 = 2097151 & (load_3(c->v + 13) >> 1);
    int64_t c6 = 2097151 & (load_4(c->v + 15) >> 6);
    int64_t c7 = 2097151 & (load_3(c->v + 18) >> 3);
    int64_t c8 = 2097151 & load_3(c->v + 21);
    int64_t c9 = 2097151 & (load_4(c->v + 23) >> 5);
    int64_t c10 = 2097151 & (load_3(c->v + 26) >> 2);
    int64_t c11 = (load_4(c->v + 28) >> 7);
    int64_t s0;
    int64_t s1;
    int64_t s2;
    int64_t s3;
    int64_t s4;
    int64_t s5;
    int64_t s6;
    int64_t s7;
    int64_t s8;
    int64_t s9;
    int64_t s10;
    int64_t s11;
    int64_t s12;
    int64_t s13;
    int64_t s14;
    int64_t s15;
    int64_t s16;
    int64_t s17;
    int64_t s18;
    int64_t s19;
    int64_t s20;
    int64_t s21;
    int64_t s22;
    int64_t s23;
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;
    int64_t carry10;
    int64_t carry11;
    int64_t carry12;
    int64_t carry13;
    int64_t carry14;
    int64_t carry15;
    int64_t carry16;
    int64_t carry17;
    int64_t carry18;
    int64_t carry19;
    int64_t carry20;
    int64_t carry21;
    int64_t carry22;

    s0 = c0 + a0 * b0;
    s1 = c1 + a0 * b1 + a1 * b0;
    s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0;
    s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0;
    s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1 +
          a10 * b0;
    s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 +
          a10 * b1 + a11 * b0;
    s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 + a10 * b2 +
          a11 * b1;
    s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2;
    s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
    s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
    s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    s20 = a9 * b11 + a10 * b10 + a11 * b9;
    s21 = a10 * b11 + a11 * b10;
    s22 = a11 * b11;
    s23 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= int64_lshift21(carry12);
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= int64_lshift21(carry14);
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= int64_lshift21(carry16);
    carry18 = (s18 + (1 << 20)) >> 21;
    s19 += carry18;
    s18 -= int64_lshift21(carry18);
    carry20 = (s20 + (1 << 20)) >> 21;
    s21 += carry20;
    s20 -= int64_lshift21(carry20);
    carry22 = (s22 + (1 << 20)) >> 21;
    s23 += carry22;
    s22 -= int64_lshift21(carry22);

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= int64_lshift21(carry13);
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= int64_lshift21(carry15);
    carry17 = (s17 + (1 << 20)) >> 21;
    s18 += carry17;
    s17 -= int64_lshift21(carry17);
    carry19 = (s19 + (1 << 20)) >> 21;
    s20 += carry19;
    s19 -= int64_lshift21(carry19);
    carry21 = (s21 + (1 << 20)) >> 21;
    s22 += carry21;
    s21 -= int64_lshift21(carry21);

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    s22 = 0;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    s21 = 0;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    s20 = 0;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    s19 = 0;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    s18 = 0;

    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= int64_lshift21(carry12);
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= int64_lshift21(carry14);
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= int64_lshift21(carry16);

    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= int64_lshift21(carry13);
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= int64_lshift21(carry15);

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    s17 = 0;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    s16 = 0;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    s15 = 0;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    s14 = 0;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    s13 = 0;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= int64_lshift21(carry11);

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= int64_lshift21(carry0);
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= int64_lshift21(carry1);
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= int64_lshift21(carry2);
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= int64_lshift21(carry3);
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= int64_lshift21(carry4);
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= int64_lshift21(carry5);
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= int64_lshift21(carry6);
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= int64_lshift21(carry7);
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= int64_lshift21(carry8);
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= int64_lshift21(carry9);
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= int64_lshift21(carry10);

    s->v[0] = s0 >> 0;
    s->v[1] = s0 >> 8;
    s->v[2] = (s0 >> 16) | (s1 << 5);
    s->v[3] = s1 >> 3;
    s->v[4] = s1 >> 11;
    s->v[5] = (s1 >> 19) | (s2 << 2);
    s->v[6] = s2 >> 6;
    s->v[7] = (s2 >> 14) | (s3 << 7);
    s->v[8] = s3 >> 1;
    s->v[9] = s3 >> 9;
    s->v[10] = (s3 >> 17) | (s4 << 4);
    s->v[11] = s4 >> 4;
    s->v[12] = s4 >> 12;
    s->v[13] = (s4 >> 20) | (s5 << 1);
    s->v[14] = s5 >> 7;
    s->v[15] = (s5 >> 15) | (s6 << 6);
    s->v[16] = s6 >> 2;
    s->v[17] = s6 >> 10;
    s->v[18] = (s6 >> 18) | (s7 << 3);
    s->v[19] = s7 >> 5;
    s->v[20] = s7 >> 13;
    s->v[21] = s8 >> 0;
    s->v[22] = s8 >> 8;
    s->v[23] = (s8 >> 16) | (s9 << 5);
    s->v[24] = s9 >> 3;
    s->v[25] = s9 >> 11;
    s->v[26] = (s9 >> 19) | (s10 << 2);
    s->v[27] = s10 >> 6;
    s->v[28] = (s10 >> 14) | (s11 << 7);
    s->v[29] = s11 >> 1;
    s->v[30] = s11 >> 9;
    s->v[31] = s11 >> 17;
}

#ifdef TODO_SIGNCRYPT
void o1c_scalar25519_negate(o1c_scalar25519_t neg, const o1c_scalar25519_t s) {
    uint8_t neg_[o1c_scalar25519_NONREDUCED_BYTES] = {0}, s_[o1c_scalar25519_NONREDUCED_BYTES] = {0};
    memcpy(neg_ + o1c_scalar25519_BYTES, L, o1c_scalar25519_BYTES);
    memcpy(s_, s->v, o1c_scalar25519_BYTES);
    uint_fast16_t c = 0;
    size_t i;
    for (i = 0; i < o1c_scalar25519_NONREDUCED_BYTES; ++i) {
        c = (uint_fast16_t) neg_[i] - (uint_fast16_t) s->v[i] - c;
        neg_[i] = (uint8_t) c;
        c = (c >> 8) & 1;
    }
    o1c_scalar25519_reduce(neg, neg_);
}
#endif
