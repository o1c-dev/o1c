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

import dev.o1c.primitive.CipherKey;
import dev.o1c.spi.InvalidAuthenticationTagException;
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;

class AsconCipherKey implements CipherKey {
    private static final int RATE = 8;
    private static final long IV = 0x80400c0600000000L;

    private final long[] state = new long[5];
    private final long keyHigh;
    private final long keyLow;

    AsconCipherKey(long keyHigh, long keyLow) {
        this.keyHigh = keyHigh;
        this.keyLow = keyLow;
    }

    @Override
    public int nonceSize() {
        return 16;
    }

    @Override
    public int tagSize() {
        return 16;
    }

    @Override
    public void encrypt(
            byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length, byte @NotNull [] out,
            int outOffset, byte @NotNull [] tag, int tagOffset) {
        if (outOffset + length > out.length) {
            throw new BufferOverflowException();
        }
        if (tagOffset + tagSize() > tag.length) {
            throw new BufferOverflowException();
        }
        init(nonce, context);
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
        state[1] ^= keyHigh;
        state[2] ^= keyLow;
        Ascon.ascon12(state);
        state[3] ^= keyHigh;
        state[4] ^= keyLow;
        ByteOps.packLongBE(state[3], tag, tagOffset);
        ByteOps.packLongBE(state[4], tag, tagOffset + RATE);
    }

    @Override
    public void decrypt(
            byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length, byte @NotNull [] tag,
            int tagOffset, byte @NotNull [] out, int outOffset) {
        if (outOffset + length > out.length) {
            throw new BufferOverflowException();
        }
        if (tagOffset + tagSize() > tag.length) {
            throw new BufferUnderflowException();
        }
        init(nonce, context);
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
        state[1] ^= keyHigh;
        state[2] ^= keyLow;
        Ascon.ascon12(state);
        state[3] ^= keyHigh;
        state[4] ^= keyLow;
        // verify tag
        if ((state[3] ^ ByteOps.unpackLongBE(tag, tagOffset) | (state[4] ^ ByteOps.unpackLongBE(tag, tagOffset + RATE))) != 0) {
            throw new InvalidAuthenticationTagException("Tag mismatch");
        }
    }

    private void init(byte[] nonce, byte[] context) {
        checkNonceSize(nonce.length);
        state[0] = IV;
        state[1] = keyHigh;
        state[2] = keyLow;
        ByteOps.unpackLongsBE(nonce, 0, 2, state, 3);
        Ascon.ascon12(state);
        state[3] ^= keyHigh;
        state[4] ^= keyLow;
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
