/*
 * ISC License
 *
 * Copyright (c) 2020, Matt Sicker
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

package dev.o1c.lwc.ascon;

import dev.o1c.primitive.AeadCipher;
import dev.o1c.spi.InvalidAuthenticationTagException;
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

import javax.crypto.SecretKey;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;

public class AsconAeadCipher implements AeadCipher {
    private static final int KEY_SIZE = 16;
    private static final int NONCE_SIZE = 16;
    private static final int TAG_SIZE = 16;
    private static final int RATE = 8;
    private static final String ALGORITHM = "Ascon128";
    private static final long IV = (long) KEY_SIZE * Byte.SIZE << 56 | (long) RATE * Byte.SIZE << 48 | 12L << 40 | 6L << 32;

    private final long[] state = new long[5];

    @Override
    public int keySize() {
        return KEY_SIZE;
    }

    @Override
    public int nonceSize() {
        return NONCE_SIZE;
    }

    @Override
    public int tagSize() {
        return TAG_SIZE;
    }

    @Override
    public @NotNull String algorithm() {
        return ALGORITHM;
    }

    @Override
    public void encrypt(
            @NotNull SecretKey key, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset,
            int length, byte @NotNull [] out, int outOffset, byte @NotNull [] tag, int tagOffset) {
        byte[] keyData = key.getEncoded();
        checkKeySize(keyData.length);
        checkNonceSize(nonce.length);
        if (outOffset + length > out.length) {
            throw new BufferOverflowException();
        }
        if (tagOffset + TAG_SIZE > tag.length) {
            throw new BufferOverflowException();
        }
        final long k0 = ByteOps.unpackLongBE(keyData, 0);
        final long k1 = ByteOps.unpackLongBE(keyData, RATE);
        final long n0 = ByteOps.unpackLongBE(nonce, 0);
        final long n1 = ByteOps.unpackLongBE(nonce, RATE);
        init(k0, k1, n0, n1, context);
        // plaintext
        while (length >= RATE) {
            state[0] ^= ByteOps.unpackLongBE(in, offset);
            ByteOps.packLongBE(state[0], out, outOffset);
            Ascon.ascon6(state);
            offset += RATE;
            outOffset += RATE;
            length -= RATE;
        }
        state[0] ^= ByteOps.unpackLongBE(in, offset, length);
        state[0] ^= 1L << 63 - length * Byte.SIZE;
        ByteOps.packLongBE(state[0], out, outOffset, length);
        // finalization
        state[1] ^= k0;
        state[2] ^= k1;
        Ascon.ascon12(state);
        state[3] ^= k0;
        state[4] ^= k1;
        ByteOps.packLongBE(state[3], tag, tagOffset);
        ByteOps.packLongBE(state[4], tag, tagOffset + RATE);
    }

    @Override
    public void decrypt(
            @NotNull SecretKey key, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset,
            int length, byte @NotNull [] tag, int tagOffset, byte @NotNull [] out, int outOffset) {
        byte[] keyData = key.getEncoded();
        checkKeySize(keyData.length);
        checkNonceSize(nonce.length);
        if (tagOffset + TAG_SIZE > tag.length) {
            throw new BufferUnderflowException();
        }
        if (outOffset + length > out.length) {
            throw new BufferOverflowException();
        }
        final long k0 = ByteOps.unpackLongBE(keyData, 0);
        final long k1 = ByteOps.unpackLongBE(keyData, RATE);
        final long n0 = ByteOps.unpackLongBE(nonce, 0);
        final long n1 = ByteOps.unpackLongBE(nonce, RATE);
        init(k0, k1, n0, n1, context);
        // plaintext
        while (length >= RATE) {
            long c0 = ByteOps.unpackLongBE(in, offset);
            ByteOps.packLongBE(state[0] ^ c0, out, outOffset);
            state[0] = c0;
            Ascon.ascon6(state);
            offset += RATE;
            outOffset += RATE;
            length -= RATE;
        }
        long c0 = ByteOps.unpackLongBE(in, offset, length);
        ByteOps.packLongBE(state[0] ^ c0, out, outOffset, length);
        state[0] &= ~byteMask(length);
        state[0] |= c0;
        state[0] ^= 1L << 63 - length * Byte.SIZE;
        // finalization
        state[1] ^= k0;
        state[2] ^= k1;
        Ascon.ascon12(state);
        state[3] ^= k0;
        state[4] ^= k1;
        // verify tag
        if ((state[3] ^ ByteOps.unpackLongBE(tag, tagOffset) | (state[4] ^ ByteOps.unpackLongBE(tag, tagOffset + RATE))) != 0) {
            throw new InvalidAuthenticationTagException("Tag mismatch");
        }
    }

    private void init(long k0, long k1, long n0, long n1, byte[] context) {
        state[0] = IV;
        state[1] = k0;
        state[2] = k1;
        state[3] = n0;
        state[4] = n1;
        Ascon.ascon12(state);
        state[3] ^= k0;
        state[4] ^= k1;
        int ad = 0, adLen = context.length;
        if (adLen > 0) {
            while (adLen >= RATE) {
                state[0] ^= ByteOps.unpackLongBE(context, ad);
                Ascon.ascon6(state);
                adLen -= RATE;
                ad += RATE;
            }
            state[0] ^= ByteOps.unpackLongBE(context, ad, adLen);
            state[0] ^= 1L << 63 - adLen * Byte.SIZE;
            Ascon.ascon6(state);
        }
        state[4] ^= 1;
    }

    private static long byteMask(int n) {
        long x = 0;
        for (int i = 0; i < n; i++) {
            x |= 0xffL << 56 - i * Byte.SIZE;
        }
        return x;
    }
}
