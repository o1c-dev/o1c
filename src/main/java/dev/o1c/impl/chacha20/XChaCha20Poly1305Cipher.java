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
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

/**
 * Implements the extended-nonce cipher XChaCha20-Poly1305.
 *
 * @see <a href="https://tools.ietf.org/html/rfc8439">RFC 8439 (ChaCha20-Poly1305)</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/">Draft XChaCha20-Poly1305</a>
 */
public class XChaCha20Poly1305Cipher implements Cipher {
    private final ChaCha20 hChaCha = new ChaCha20();
    private final Cipher innerCipher = new ChaCha20Poly1305Cipher();

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public int nonceLength() {
        return 24;
    }

    @Override
    public void init(byte @NotNull [] key, byte @NotNull [] nonce, byte @NotNull [] context) {
        checkKeyLength(key.length);
        checkNonceLength(nonce.length);
        hChaCha.initKey(key);
        byte[] hNonce = Arrays.copyOf(nonce, 16);
        byte[] sNonce = Arrays.copyOfRange(nonce, 12, 24);
        ByteOps.overwriteWithZeroes(sNonce, 0, 4);
        innerCipher.init(hChaCha.hKey(hNonce), sNonce, context);
    }

    @Override
    public int tagLength() {
        return 16;
    }

    @Override
    public void encrypt(
            byte @NotNull [] plaintext, int ptOffset, int ptLength, byte @NotNull [] ciphertext, int ctOffset,
            byte @NotNull [] tag, int tagOffset) {
        innerCipher.encrypt(plaintext, ptOffset, ptLength, ciphertext, ctOffset, tag, tagOffset);
    }

    @Override
    public void decrypt(
            byte @NotNull [] ciphertext, int ctOffset, int ctLength, byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] plaintext, int ptOffset) {
        innerCipher.decrypt(ciphertext, ctOffset, ctLength, tag, tagOffset, plaintext, ptOffset);
    }
}
