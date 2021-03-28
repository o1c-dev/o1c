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

import dev.o1c.spi.Cipher;
import dev.o1c.spi.InvalidAuthenticationTagException;
import dev.o1c.util.Validator;
import org.jetbrains.annotations.NotNull;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Implements RFC 8439 version of ChaCha20-Poly1305.
 *
 * @see <a href="https://tools.ietf.org/html/rfc8439">RFC 8439</a>
 */
public class ChaCha20Poly1305Cipher implements Cipher {
    private final ChaCha20 cipher = new ChaCha20();
    private final Poly1305 authenticator = new Poly1305();
    private long contextLength = -1;

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public int nonceLength() {
        return 12;
    }

    @Override
    public void init(byte @NotNull [] key, byte @NotNull [] nonce, byte @NotNull [] context) {
        checkKeyLength(key.length);
        checkNonceLength(nonce.length);
        cipher.initKey(key);
        cipher.initNonce(nonce);
        cipher.initCounter(0);
        authenticator.init(cipher.polyKey());
        authenticator.updatePad(context, 0, context.length);
        contextLength = context.length;
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
        if (contextLength < 0) {
            throw new IllegalStateException("Cipher must be initialized");
        }
        cipher.crypt(plaintext, ptOffset, ptLength, ciphertext, ctOffset);
        authenticator.updatePad(ciphertext, ctOffset, ptLength);
        authenticator.updateLengths(contextLength, ptLength);
        authenticator.computeMac(tag, tagOffset);
        contextLength = -1;
    }

    @Override
    public void decrypt(
            byte @NotNull [] ciphertext, int ctOffset, int ctLength, byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] plaintext, int ptOffset) {
        Validator.checkBufferArgs(ciphertext, ctOffset, ctLength);
        Validator.checkBufferArgs(tag, tagOffset, tagLength());
        Validator.checkBufferArgs(plaintext, ptOffset, ctLength);
        if (contextLength < 0) {
            throw new IllegalStateException("Cipher must be initialized");
        }
        authenticator.updatePad(ciphertext, ctOffset, ctLength);
        authenticator.updateLengths(contextLength, ctLength);
        byte[] actualTag = authenticator.computeMac();
        byte[] expectedTag = Arrays.copyOfRange(tag, tagOffset, tagOffset + tagLength());
        if (!MessageDigest.isEqual(expectedTag, actualTag)) {
            throw new InvalidAuthenticationTagException("Tag mismatch");
        }
        cipher.crypt(ciphertext, ctOffset, ctLength, plaintext, ptOffset);
        contextLength = -1;
    }
}
