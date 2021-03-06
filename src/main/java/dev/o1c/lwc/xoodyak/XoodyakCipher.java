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

package dev.o1c.lwc.xoodyak;

import dev.o1c.spi.Cipher;
import dev.o1c.spi.InvalidAuthenticationTagException;
import dev.o1c.util.Validator;
import org.jetbrains.annotations.NotNull;

import java.security.MessageDigest;
import java.util.Arrays;

class XoodyakCipher implements Cipher {
    private final Xoodyak xoodyak = new Xoodyak();

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
        xoodyak.initialize(key);
        xoodyak.absorb(nonce, 0, nonce.length);
        xoodyak.absorb(context, 0, context.length);
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
        xoodyak.encrypt(plaintext, ptOffset, ptLength, ciphertext, ctOffset);
        xoodyak.squeeze(tag, tagOffset, tagLength());
        xoodyak.ratchet();
    }

    @Override
    public void decrypt(
            byte @NotNull [] ciphertext, int ctOffset, int ctLength, byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] plaintext, int ptOffset) {
        Validator.checkBufferArgs(ciphertext, ctOffset, ctLength);
        Validator.checkBufferArgs(tag, tagOffset, tagLength());
        Validator.checkBufferArgs(plaintext, ptOffset, ctLength);
        xoodyak.decrypt(ciphertext, ctOffset, ctLength, plaintext, ptOffset);
        byte[] expected = Arrays.copyOfRange(tag, tagOffset, tagOffset + tagLength());
        byte[] actual = new byte[tagLength()];
        xoodyak.squeeze(actual, 0, actual.length);
        xoodyak.ratchet();
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new InvalidAuthenticationTagException("Tag mismatch");
        }
    }
}
