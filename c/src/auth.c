// adapted from poly1305-donna; public domain or MIT license

#include <assert.h>

static_assert(ARCH_WORD_BITS == 32 || ARCH_WORD_BITS == 64, "Unsupported architecture");

#include "o1c.h"
#include "mem.h"

#if (ARCH_WORD_BITS == 32)
#define RH_LIMBS 5
#define PAD_LIMBS 4
typedef unsigned long limb_t;
#else
#define RH_LIMBS 3
#define PAD_LIMBS 2
typedef unsigned long long limb_t;
#endif

#define poly1305_BLOCK_SIZE 16

typedef struct poly1305_state_internal_t {
    limb_t r[RH_LIMBS];
    limb_t h[RH_LIMBS];
    limb_t pad[PAD_LIMBS];
    unsigned long leftover;
    unsigned char buffer[poly1305_BLOCK_SIZE];
    unsigned char final;
} poly1305_state_internal_t;

void o1c_auth(uint8_t t[o1c_auth_TAG_BYTES], const uint8_t *m, unsigned long bytes, const uint8_t k[o1c_auth_KEY_BYTES]) {
    o1c_auth_t ctx;
    o1c_auth_key_setup(ctx, k);
    o1c_auth_update(ctx, m, bytes);
    o1c_auth_final(ctx, t);
}

void o1c_auth_key_setup(o1c_auth_t ctx, const uint8_t k[o1c_auth_KEY_BYTES]) {
    poly1305_state_internal_t *st = (poly1305_state_internal_t *) ctx->state;
#if (ARCH_WORD_BITS == 32)
    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    st->r[0] = (load32_le(&k[ 0])     ) & 0x3ffffff;
    st->r[1] = (load32_le(&k[ 3]) >> 2) & 0x3ffff03;
    st->r[2] = (load32_le(&k[ 6]) >> 4) & 0x3ffc0ff;
    st->r[3] = (load32_le(&k[ 9]) >> 6) & 0x3f03fff;
    st->r[4] = (load32_le(&k[12]) >> 8) & 0x00fffff;

    /* h = 0 */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;

    /* save pad for later */
    st->pad[0] = load32_le(&k[16]);
    st->pad[1] = load32_le(&k[20]);
    st->pad[2] = load32_le(&k[24]);
    st->pad[3] = load32_le(&k[28]);

    st->leftover = 0;
    st->final = 0;
#else
    unsigned long long t0, t1;

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    t0 = load64_le(&k[0]);
    t1 = load64_le(&k[8]);

    st->r[0] = (t0) & 0xffc0fffffff;
    st->r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
    st->r[2] = ((t1 >> 24)) & 0x00ffffffc0f;

    /* h = 0 */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;

    /* save pad for later */
    st->pad[0] = load64_le(&k[16]);
    st->pad[1] = load64_le(&k[24]);

    st->leftover = 0;
    st->final = 0;
#endif
}

#if defined(_MSC_VER)
#include <intrin.h>

typedef struct uint128_t {
    unsigned long long lo;
    unsigned long long hi;
} uint128_t;

#define MUL(out, x, y) out.lo = _umul128((x), (y), &out.hi)
#define ADD(out, in) { unsigned long long t = out.lo; out.lo += in.lo; out.hi += (out.lo < t) + in.hi; }
#define ADDLO(out, in) { unsigned long long t = out.lo; out.lo += in; out.hi += (out.lo < t); }
#define SHR(in, shift) (__shiftright128(in.lo, in.hi, (shift)))
#define LO(in) (in.lo)

#elif defined(__GNUC__)

#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;
#else
typedef unsigned uint128_t __attribute__((mode(TI)));
#endif

#define MUL(out, x, y) out = ((uint128_t)x * y)
#define ADD(out, in) out += in
#define ADDLO(out, in) out += in
#define SHR(in, shift) (unsigned long long)(in >> (shift))
#define LO(in) (unsigned long long)(in)

#endif

void poly1305_blocks(poly1305_state_internal_t *st, const uint8_t *m, unsigned long bytes) {
#if (ARCH_WORD_BITS == 32)
    const unsigned long hibit = (st->final) ? 0 : (1UL << 24); /* 1 << 128 */
	unsigned long r0,r1,r2,r3,r4;
	unsigned long s1,s2,s3,s4;
	unsigned long h0,h1,h2,h3,h4;
	unsigned long long d0,d1,d2,d3,d4;
	unsigned long c;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];
	r3 = st->r[3];
	r4 = st->r[4];

	s1 = r1 * 5;
	s2 = r2 * 5;
	s3 = r3 * 5;
	s4 = r4 * 5;

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	while (bytes >= poly1305_BLOCK_SIZE) {
		/* h += m[i] */
		h0 += (load32_le(m+ 0)     ) & 0x3ffffff;
		h1 += (load32_le(m+ 3) >> 2) & 0x3ffffff;
		h2 += (load32_le(m+ 6) >> 4) & 0x3ffffff;
		h3 += (load32_le(m+ 9) >> 6) & 0x3ffffff;
		h4 += (load32_le(m+12) >> 8) | hibit;

		/* h *= r */
		d0 = ((unsigned long long)h0 * r0) + ((unsigned long long)h1 * s4) + ((unsigned long long)h2 * s3) + ((unsigned long long)h3 * s2) + ((unsigned long long)h4 * s1);
		d1 = ((unsigned long long)h0 * r1) + ((unsigned long long)h1 * r0) + ((unsigned long long)h2 * s4) + ((unsigned long long)h3 * s3) + ((unsigned long long)h4 * s2);
		d2 = ((unsigned long long)h0 * r2) + ((unsigned long long)h1 * r1) + ((unsigned long long)h2 * r0) + ((unsigned long long)h3 * s4) + ((unsigned long long)h4 * s3);
		d3 = ((unsigned long long)h0 * r3) + ((unsigned long long)h1 * r2) + ((unsigned long long)h2 * r1) + ((unsigned long long)h3 * r0) + ((unsigned long long)h4 * s4);
		d4 = ((unsigned long long)h0 * r4) + ((unsigned long long)h1 * r3) + ((unsigned long long)h2 * r2) + ((unsigned long long)h3 * r1) + ((unsigned long long)h4 * r0);

		/* (partial) h %= p */
		              c = (unsigned long)(d0 >> 26); h0 = (unsigned long)d0 & 0x3ffffff;
		d1 += c;      c = (unsigned long)(d1 >> 26); h1 = (unsigned long)d1 & 0x3ffffff;
		d2 += c;      c = (unsigned long)(d2 >> 26); h2 = (unsigned long)d2 & 0x3ffffff;
		d3 += c;      c = (unsigned long)(d3 >> 26); h3 = (unsigned long)d3 & 0x3ffffff;
		d4 += c;      c = (unsigned long)(d4 >> 26); h4 = (unsigned long)d4 & 0x3ffffff;
		h0 += c * 5;  c =                (h0 >> 26); h0 =                h0 & 0x3ffffff;
		h1 += c;

		m += poly1305_BLOCK_SIZE;
		bytes -= poly1305_BLOCK_SIZE;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
	st->h[3] = h3;
	st->h[4] = h4;
#else
    const unsigned long long hibit = (st->final) ? 0 : ((unsigned long long) 1 << 40); /* 1 << 128 */
    unsigned long long r0, r1, r2;
    unsigned long long s1, s2;
    unsigned long long h0, h1, h2;
    unsigned long long c;
    uint128_t d0, d1, d2, d;

    r0 = st->r[0];
    r1 = st->r[1];
    r2 = st->r[2];

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];

    s1 = r1 * (5 << 2);
    s2 = r2 * (5 << 2);

    while (bytes >= poly1305_BLOCK_SIZE) {
        unsigned long long t0, t1;

        /* h += m[i] */
        t0 = load64_le(&m[0]);
        t1 = load64_le(&m[8]);

        h0 += ((t0) & 0xfffffffffff);
        h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
        h2 += (((t1 >> 24)) & 0x3ffffffffff) | hibit;

        /* h *= r */
        MUL(d0, h0, r0);
        MUL(d, h1, s2);
        ADD(d0, d);
        MUL(d, h2, s1);
        ADD(d0, d);
        MUL(d1, h0, r1);
        MUL(d, h1, r0);
        ADD(d1, d);
        MUL(d, h2, s2);
        ADD(d1, d);
        MUL(d2, h0, r2);
        MUL(d, h1, r1);
        ADD(d2, d);
        MUL(d, h2, r0);
        ADD(d2, d);

        /* (partial) h %= p */
        c = SHR(d0, 44);
        h0 = LO(d0) & 0xfffffffffff;
        ADDLO(d1, c);
        c = SHR(d1, 44);
        h1 = LO(d1) & 0xfffffffffff;
        ADDLO(d2, c);
        c = SHR(d2, 42);
        h2 = LO(d2) & 0x3ffffffffff;
        h0 += c * 5;
        c = (h0 >> 44);
        h0 = h0 & 0xfffffffffff;
        h1 += c;

        m += poly1305_BLOCK_SIZE;
        bytes -= poly1305_BLOCK_SIZE;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
#endif
}

void o1c_auth_update(o1c_auth_t ctx, const uint8_t *m, unsigned long bytes) {
    poly1305_state_internal_t *st = (poly1305_state_internal_t *) ctx->state;
    unsigned long i;

    /* handle leftover */
    if (st->leftover) {
        unsigned long want = (poly1305_BLOCK_SIZE - st->leftover);
        if (want > bytes)
            want = bytes;
        for (i = 0; i < want; i++)
            st->buffer[st->leftover + i] = m[i];
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < poly1305_BLOCK_SIZE)
            return;
        poly1305_blocks(st, st->buffer, poly1305_BLOCK_SIZE);
        st->leftover = 0;
    }

    /* process full blocks */
    if (bytes >= poly1305_BLOCK_SIZE) {
        unsigned long want = (bytes & ~(poly1305_BLOCK_SIZE - 1));
        poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }

    /* store leftover */
    if (bytes) {
        for (i = 0; i < bytes; i++)
            st->buffer[st->leftover + i] = m[i];
        st->leftover += bytes;
    }
}

O1C_NOINLINE void o1c_auth_final(o1c_auth_t ctx, uint8_t t[o1c_auth_TAG_BYTES]) {
    poly1305_state_internal_t *st = (poly1305_state_internal_t *) ctx->state;
#if (ARCH_WORD_BITS == 32)
    unsigned long h0,h1,h2,h3,h4,c;
	unsigned long g0,g1,g2,g3,g4;
	unsigned long long f;
	unsigned long mask;

	/* process the remaining block */
	if (st->leftover) {
		size_t i = st->leftover;
		st->buffer[i++] = 1;
		for (; i < poly1305_BLOCK_SIZE; i++)
			st->buffer[i] = 0;
		st->final = 1;
		poly1305_blocks(st, st->buffer, poly1305_BLOCK_SIZE);
	}

	/* fully carry h */
	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	             c = h1 >> 26; h1 = h1 & 0x3ffffff;
	h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
	h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
	h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
	h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
	h1 +=     c;

	/* compute h + -p */
	g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
	g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
	g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
	g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
	g4 = h4 + c - (1UL << 26);

	/* select h if h < p, or h + -p if h >= p */
	mask = (g4 >> ((sizeof(unsigned long) * 8) - 1)) - 1;
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	/* h = h % (2^128) */
	h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
	h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
	h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

	/* mac = (h + pad) % (2^128) */
	f = (unsigned long long)h0 + st->pad[0]            ; h0 = (unsigned long)f;
	f = (unsigned long long)h1 + st->pad[1] + (f >> 32); h1 = (unsigned long)f;
	f = (unsigned long long)h2 + st->pad[2] + (f >> 32); h2 = (unsigned long)f;
	f = (unsigned long long)h3 + st->pad[3] + (f >> 32); h3 = (unsigned long)f;

	store32_le(t +  0, h0);
	store32_le(t +  4, h1);
	store32_le(t +  8, h2);
	store32_le(t + 12, h3);

	/* zero out the state */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->h[3] = 0;
	st->h[4] = 0;
	st->r[0] = 0;
	st->r[1] = 0;
	st->r[2] = 0;
	st->r[3] = 0;
	st->r[4] = 0;
	st->pad[0] = 0;
	st->pad[1] = 0;
	st->pad[2] = 0;
	st->pad[3] = 0;
#else
    unsigned long long h0,h1,h2,c;
    unsigned long long g0,g1,g2;
    unsigned long long t0,t1;

    /* process the remaining block */
    if (st->leftover) {
        unsigned long i = st->leftover;
        st->buffer[i] = 1;
        for (i = i + 1; i < poly1305_BLOCK_SIZE; i++)
            st->buffer[i] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, poly1305_BLOCK_SIZE);
    }

    /* fully carry h */
    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];

    c = (h1 >> 44); h1 &= 0xfffffffffff;
    h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
    h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
    h1 += c;     c = (h1 >> 44); h1 &= 0xfffffffffff;
    h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
    h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
    h1 += c;

    /* compute h + -p */
    g0 = h0 + 5; c = (g0 >> 44); g0 &= 0xfffffffffff;
    g1 = h1 + c; c = (g1 >> 44); g1 &= 0xfffffffffff;
    g2 = h2 + c - ((unsigned long long)1 << 42);

    /* select h if h < p, or h + -p if h >= p */
    c = (g2 >> ((sizeof(unsigned long long) * 8) - 1)) - 1;
    g0 &= c;
    g1 &= c;
    g2 &= c;
    c = ~c;
    h0 = (h0 & c) | g0;
    h1 = (h1 & c) | g1;
    h2 = (h2 & c) | g2;

    /* h = (h + pad) */
    t0 = st->pad[0];
    t1 = st->pad[1];

    h0 += (( t0                    ) & 0xfffffffffff)    ; c = (h0 >> 44); h0 &= 0xfffffffffff;
    h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c; c = (h1 >> 44); h1 &= 0xfffffffffff;
    h2 += (((t1 >> 24)             ) & 0x3ffffffffff) + c;                 h2 &= 0x3ffffffffff;

    /* mac = h % (2^128) */
    h0 = ((h0      ) | (h1 << 44));
    h1 = ((h1 >> 20) | (h2 << 24));

    store64_le(&t[0], h0);
    store64_le(&t[8], h1);

    /* zero out the state */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->r[0] = 0;
    st->r[1] = 0;
    st->r[2] = 0;
    st->pad[0] = 0;
    st->pad[1] = 0;
#endif
}
