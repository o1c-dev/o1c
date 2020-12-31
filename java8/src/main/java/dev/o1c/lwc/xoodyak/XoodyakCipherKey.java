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

package dev.o1c.lwc.xoodyak;

import dev.o1c.primitive.CipherKey;
import dev.o1c.spi.InvalidAuthenticationTagException;
import org.jetbrains.annotations.NotNull;

import java.security.MessageDigest;
import java.util.Arrays;

class XoodyakCipherKey implements CipherKey {
    private final Xoodyak xoodyak = new Xoodyak();
    private final byte[] key;

    XoodyakCipherKey(byte @NotNull [] key) {
        this.key = key;
        xoodyak.initialize(key);
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
        checkNonceSize(nonce.length);
        xoodyak.initialize(key);
        xoodyak.absorb(nonce, 0, nonce.length);
        xoodyak.absorb(context, 0, context.length);
        xoodyak.encrypt(in, offset, length, out, outOffset);
        xoodyak.squeeze(tag, tagOffset, tagSize());
        xoodyak.ratchet();
    }

    @Override
    public void decrypt(
            byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length, byte @NotNull [] tag,
            int tagOffset, byte @NotNull [] out, int outOffset) {
        checkNonceSize(nonce.length);
        xoodyak.initialize(key);
        xoodyak.absorb(nonce, 0, nonce.length);
        xoodyak.absorb(context, 0, context.length);
        xoodyak.decrypt(in, offset, length, out, outOffset);
        byte[] expected = Arrays.copyOfRange(tag, tagOffset, tagOffset + tagSize());
        byte[] actual = new byte[tagSize()];
        xoodyak.squeeze(actual, 0, actual.length);
        xoodyak.ratchet();
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new InvalidAuthenticationTagException("Tag mismatch");
        }
    }
}
