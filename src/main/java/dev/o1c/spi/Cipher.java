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

package dev.o1c.spi;

import org.jetbrains.annotations.NotNull;

public interface Cipher {
    int keyLength();

    default void checkKeyLength(int keyLength) {
        if (keyLength != keyLength()) {
            throw new InvalidKeyException("Key must be " + keyLength() + " bytes but got " + keyLength);
        }
    }

    int nonceLength();

    default void checkNonceLength(int nonceLength) {
        if (nonceLength != nonceLength()) {
            throw new IllegalArgumentException("Nonce must be " + nonceLength() + " bytes but got " + nonceLength);
        }
    }

    void init(byte @NotNull [] key, byte @NotNull [] nonce, byte @NotNull [] context);

    int tagLength();

    void encrypt(
            byte @NotNull [] plaintext, int ptOffset, int ptLength,
            byte @NotNull [] ciphertext, int ctOffset,
            byte @NotNull [] tag, int tagOffset);

    default byte @NotNull [] encrypt(byte @NotNull [] plaintext) {
        byte[] ciphertext = new byte[plaintext.length + tagLength()];
        encrypt(plaintext, 0, plaintext.length, ciphertext, 0, ciphertext, plaintext.length);
        return ciphertext;
    }

    default byte @NotNull [] encrypt(
            byte @NotNull [] key, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] plaintext) {
        init(key, nonce, context);
        return encrypt(plaintext);
    }

    void decrypt(
            byte @NotNull [] ciphertext, int ctOffset, int ctLength,
            byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] plaintext, int ptOffset);

    default byte @NotNull [] decrypt(byte @NotNull [] ciphertext) {
        if (ciphertext.length < tagLength()) {
            throw new InvalidAuthenticationTagException("Invalid ciphertext");
        }
        byte[] plaintext = new byte[ciphertext.length - tagLength()];
        decrypt(ciphertext, 0, plaintext.length, ciphertext, plaintext.length, plaintext, 0);
        return plaintext;
    }

    default byte @NotNull [] decrypt(
            byte @NotNull [] key, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] ciphertext) {
        init(key, nonce, context);
        return decrypt(ciphertext);
    }

}
