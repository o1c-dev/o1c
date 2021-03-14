/*
 * ISC License
 *
 * Copyright (c) 2021, Matt Sicker
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * SPDX-License-Identifier: ISC
 */

package dev.o1c.impl.chacha20;

import dev.o1c.spi.InvalidKeyException;
import dev.o1c.util.ByteOps;

import java.nio.BufferOverflowException;

/**
 * Poly1305-Donna for computing one-time authentication codes for messages. These should never be reused for the same
 * key. Adapted from public domain code.
 */
class Poly1305 {
    private static final int BLOCK_SIZE = 16;
    private static final byte[] PADDING = new byte[BLOCK_SIZE];

    private int r0;
    private int r1;
    private int r2;
    private int r3;
    private int r4;
    private int s1;
    private int s2;
    private int s3;
    private int s4;
    private int k0;
    private int k1;
    private int k2;
    private int k3;

    private int h0;
    private int h1;
    private int h2;
    private int h3;
    private int h4;
    private final byte[] currentBlock = new byte[BLOCK_SIZE];
    private int currentBlockOffset;

    void init(byte[] key) {
        if (key.length != 32) {
            throw new InvalidKeyException("Keys must be 32 bytes");
        }

        int t0 = ByteOps.unpackIntLE(key, 0);
        int t1 = ByteOps.unpackIntLE(key, 4);
        int t2 = ByteOps.unpackIntLE(key, 8);
        int t3 = ByteOps.unpackIntLE(key, 12);

        // NOTE: The masks perform the key "clamping" implicitly
        r0 = t0 & 0x03FFFFFF;
        r1 = (t0 >>> 26 | t1 << 6) & 0x03FFFF03;
        r2 = (t1 >>> 20 | t2 << 12) & 0x03FFC0FF;
        r3 = (t2 >>> 14 | t3 << 18) & 0x03F03FFF;
        r4 = t3 >>> 8 & 0x000FFFFF;

        // Precompute multipliers
        s1 = r1 * 5;
        s2 = r2 * 5;
        s3 = r3 * 5;
        s4 = r4 * 5;

        k0 = ByteOps.unpackIntLE(key, 16);
        k1 = ByteOps.unpackIntLE(key, 20);
        k2 = ByteOps.unpackIntLE(key, 24);
        k3 = ByteOps.unpackIntLE(key, 28);
    }

    void update(byte[] in, int offset, int length) {
        while (length > 0) {
            if (currentBlockOffset == BLOCK_SIZE) {
                processBlock();
            }

            int toCopy = Math.min(length, BLOCK_SIZE - currentBlockOffset);
            System.arraycopy(in, offset, currentBlock, currentBlockOffset, toCopy);
            offset += toCopy;
            length -= toCopy;
            currentBlockOffset += toCopy;
        }
    }

    void updatePad(byte[] in, int offset, int length) {
        update(in, offset, length);
        update(PADDING, 0, (0x10 - length) & 0xf);
    }

    void updateLengths(long contextLength, long ciphertextLength) {
        byte[] block = new byte[BLOCK_SIZE];
        ByteOps.packLongLE(contextLength, block, 0);
        ByteOps.packLongLE(ciphertextLength, block, Long.BYTES);
        update(block, 0, BLOCK_SIZE);
    }

    byte[] computeMac() {
        byte[] mac = new byte[BLOCK_SIZE];
        computeMac(mac, 0);
        return mac;
    }

    void computeMac(byte[] out, int offset) {
        if (offset + BLOCK_SIZE > out.length) {
            throw new BufferOverflowException();
        }
        if (currentBlockOffset > 0) {
            processBlock();
        }

        h1 += h0 >>> 26;
        h0 &= 0x3ffffff;
        h2 += h1 >>> 26;
        h1 &= 0x3ffffff;
        h3 += h2 >>> 26;
        h2 &= 0x3ffffff;
        h4 += h3 >>> 26;
        h3 &= 0x3ffffff;
        h0 += (h4 >>> 26) * 5;
        h4 &= 0x3ffffff;
        h1 += h0 >>> 26;
        h0 &= 0x3ffffff;

        int g0, g1, g2, g3, g4, b;
        g0 = h0 + 5;
        b = g0 >>> 26;
        g0 &= 0x3ffffff;
        g1 = h1 + b;
        b = g1 >>> 26;
        g1 &= 0x3ffffff;
        g2 = h2 + b;
        b = g2 >>> 26;
        g2 &= 0x3ffffff;
        g3 = h3 + b;
        b = g3 >>> 26;
        g3 &= 0x3ffffff;
        g4 = h4 + b - (1 << 26);

        b = (g4 >>> 31) - 1;
        int nb = ~b;
        h0 = h0 & nb | g0 & b;
        h1 = h1 & nb | g1 & b;
        h2 = h2 & nb | g2 & b;
        h3 = h3 & nb | g3 & b;
        h4 = h4 & nb | g4 & b;

        long f0, f1, f2, f3;
        f0 = Integer.toUnsignedLong(h0 | h1 << 26) + Integer.toUnsignedLong(k0);
        f1 = Integer.toUnsignedLong(h1 >>> 6 | h2 << 20) + Integer.toUnsignedLong(k1);
        f2 = Integer.toUnsignedLong(h2 >>> 12 | h3 << 14) + Integer.toUnsignedLong(k2);
        f3 = Integer.toUnsignedLong(h3 >>> 18 | h4 << 8) + Integer.toUnsignedLong(k3);

        ByteOps.packIntLE((int) f0, out, offset);
        f1 += f0 >>> 32;
        ByteOps.packIntLE((int) f1, out, offset + 4);
        f2 += f1 >>> 32;
        ByteOps.packIntLE((int) f2, out, offset + 8);
        f3 += f2 >>> 32;
        ByteOps.packIntLE((int) f3, out, offset + 12);

        reset();
    }

    private void processBlock() {
        if (currentBlockOffset < BLOCK_SIZE) {
            // padding
            currentBlock[currentBlockOffset] = 1;
            for (int i = currentBlockOffset + 1; i < BLOCK_SIZE; i++) {
                currentBlock[i] = 0;
            }
        }

        long t0 = Integer.toUnsignedLong(ByteOps.unpackIntLE(currentBlock, 0));
        long t1 = Integer.toUnsignedLong(ByteOps.unpackIntLE(currentBlock, 4));
        long t2 = Integer.toUnsignedLong(ByteOps.unpackIntLE(currentBlock, 8));
        long t3 = Integer.toUnsignedLong(ByteOps.unpackIntLE(currentBlock, 12));

        h0 += t0 & 0x3ffffff;
        h1 += (t1 << 32 | t0) >>> 26 & 0x3ffffff;
        h2 += (t2 << 32 | t1) >>> 20 & 0x3ffffff;
        h3 += (t3 << 32 | t2) >>> 14 & 0x3ffffff;
        h4 += t3 >>> 8;

        if (currentBlockOffset == BLOCK_SIZE) {
            h4 += 1 << 24;
        }

        long tp0 =
                mul32x32_64(h0, r0) + mul32x32_64(h1, s4) + mul32x32_64(h2, s3) + mul32x32_64(h3, s2) + mul32x32_64(h4,
                        s1);
        long tp1 =
                mul32x32_64(h0, r1) + mul32x32_64(h1, r0) + mul32x32_64(h2, s4) + mul32x32_64(h3, s3) + mul32x32_64(h4,
                        s2);
        long tp2 =
                mul32x32_64(h0, r2) + mul32x32_64(h1, r1) + mul32x32_64(h2, r0) + mul32x32_64(h3, s4) + mul32x32_64(h4,
                        s3);
        long tp3 =
                mul32x32_64(h0, r3) + mul32x32_64(h1, r2) + mul32x32_64(h2, r1) + mul32x32_64(h3, r0) + mul32x32_64(h4,
                        s4);
        long tp4 =
                mul32x32_64(h0, r4) + mul32x32_64(h1, r3) + mul32x32_64(h2, r2) + mul32x32_64(h3, r1) + mul32x32_64(h4,
                        r0);

        h0 = (int) tp0 & 0x3ffffff;
        tp1 += tp0 >>> 26;
        h1 = (int) tp1 & 0x3ffffff;
        tp2 += tp1 >>> 26;
        h2 = (int) tp2 & 0x3ffffff;
        tp3 += tp2 >>> 26;
        h3 = (int) tp3 & 0x3ffffff;
        tp4 += tp3 >>> 26;
        h4 = (int) tp4 & 0x3ffffff;
        h0 += (int) (tp4 >>> 26) * 5;
        h1 += h0 >>> 26;
        h0 &= 0x3ffffff;

        currentBlockOffset = 0;
    }

    void reset() {
        h0 = 0;
        h1 = 0;
        h2 = 0;
        h3 = 0;
        h4 = 0;
        currentBlockOffset = 0;
        ByteOps.overwriteWithZeroes(currentBlock);
    }

    private static long mul32x32_64(int i1, int i2) {
        return Integer.toUnsignedLong(i1) * Integer.toUnsignedLong(i2);
    }
}
