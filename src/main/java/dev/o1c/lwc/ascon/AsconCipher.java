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

package dev.o1c.lwc.ascon;

import dev.o1c.spi.Cipher;
import dev.o1c.spi.InvalidAuthenticationTagException;
import dev.o1c.util.ByteOps;
import dev.o1c.util.Validator;
import org.jetbrains.annotations.NotNull;

class AsconCipher implements Cipher {
    private static final int RATE = 8;
    private static final long IV = 0x80400c0600000000L;

    private final long[] state = new long[5];
    private long keyHigh;
    private long keyLow;

    @Override
    public int keyLength() {
        return 16;
    }

    @Override
    public int nonceLength() {
        return 16;
    }

    @Override
    public void init(byte @NotNull [] key, byte @NotNull [] nonce, byte @NotNull [] context) {
        checkKeyLength(key.length);
        checkNonceLength(nonce.length);
        keyHigh = ByteOps.unpackLongBE(key, 0);
        keyLow = ByteOps.unpackLongBE(key, Long.BYTES);
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

    @Override
    public int tagLength() {
        return 16;
    }

    @Override
    public void encrypt(
            byte @NotNull [] plaintext, int ptOffset, int ptLength, byte @NotNull [] ciphertext, int ctOffset,
            byte @NotNull [] tag, int tagOffset) {
        Validator.checkBufferArgs(plaintext, ptOffset, ptLength);
        Validator.checkBufferArgs(ciphertext, ctOffset, ptLength);
        Validator.checkBufferArgs(tag, tagOffset, tagLength());
        while (ptLength >= RATE) {
            state[0] ^= ByteOps.unpackLongBE(plaintext, ptOffset);
            ByteOps.packLongBE(state[0], ciphertext, ctOffset);
            Ascon.ascon6(state);
            ptOffset += RATE;
            ctOffset += RATE;
            ptLength -= RATE;
        }
        state[0] ^= ByteOps.unpackLongBE(plaintext, ptOffset, ptLength);
        state[0] ^= 1L << 63 - ptLength * Byte.SIZE;
        ByteOps.packLongBE(state[0], ciphertext, ctOffset, ptLength);
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
            byte @NotNull [] ciphertext, int ctOffset, int ctLength, byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] plaintext, int ptOffset) {
        Validator.checkBufferArgs(ciphertext, ctOffset, ctLength);
        Validator.checkBufferArgs(tag, tagOffset, tagLength());
        Validator.checkBufferArgs(plaintext, ptOffset, ctLength);
        // plaintext
        while (ctLength >= RATE) {
            long c0 = ByteOps.unpackLongBE(ciphertext, ctOffset);
            ByteOps.packLongBE(state[0] ^ c0, plaintext, ptOffset);
            state[0] = c0;
            Ascon.ascon6(state);
            ctOffset += RATE;
            ptOffset += RATE;
            ctLength -= RATE;
        }
        long c0 = ByteOps.unpackLongBE(ciphertext, ctOffset, ctLength);
        ByteOps.packLongBE(state[0] ^ c0, plaintext, ptOffset, ctLength);
        state[0] &= ~byteMask(ctLength);
        state[0] |= c0;
        state[0] ^= 1L << 63 - ctLength * Byte.SIZE;
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

    private static long byteMask(int n) {
        long x = 0;
        for (int i = 0; i < n; i++) {
            x |= 0xffL << 56 - i * Byte.SIZE;
        }
        return x;
    }
}
