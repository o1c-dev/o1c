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
import dev.o1c.util.Validator;
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
    private State state;

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public void setKey(byte @NotNull [] key) {
        checkKeyLength(key.length);
        hChaCha.initKey(key);
        state = State.KeyInitialized;
    }

    @Override
    public int nonceLength() {
        return 24;
    }

    @Override
    public void setNonce(byte @NotNull [] nonce) {
        checkNonceLength(nonce.length);
        if (state != State.KeyInitialized) {
            throw new IllegalStateException("Nonce can only be set after key initialization or encryption/decryption");
        }
        byte[] hNonce = Arrays.copyOf(nonce, 16);
        byte[] sNonce = Arrays.copyOfRange(nonce, 12, 24);
        ByteOps.overwriteWithZeroes(sNonce, 0, 4);
        innerCipher.setKey(hChaCha.hKey(hNonce));
        innerCipher.setNonce(sNonce);
        state = State.NonceInitialized;
    }

    @Override
    public int tagLength() {
        return 16;
    }

    @Override
    public void setContext(byte @NotNull [] context, int offset, int length) {
        Validator.checkBufferArgs(context, offset, length);
        if (state != State.NonceInitialized) {
            throw new IllegalStateException("Nonce must be initialized");
        }
        innerCipher.setContext(context, offset, length);
    }

    @Override
    public void encrypt(
            byte @NotNull [] plaintext, int ptOffset, int ptLength, byte @NotNull [] ciphertext, int ctOffset,
            byte @NotNull [] tag, int tagOffset) {
        Validator.checkBufferArgs(plaintext, ptOffset, ptLength);
        Validator.checkBufferArgs(ciphertext, ctOffset, ptLength);
        Validator.checkBufferArgs(tag, tagOffset, tagLength());
        if (state != State.NonceInitialized && state != State.ContextInitialized) {
            throw new IllegalStateException("Nonce must be initialized");
        }
        innerCipher.encrypt(plaintext, ptOffset, ptLength, ciphertext, ctOffset, tag, tagOffset);
        state = State.KeyInitialized;
    }

    @Override
    public void decrypt(
            byte @NotNull [] ciphertext, int ctOffset, int ctLength, byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] plaintext, int ptOffset) {
        Validator.checkBufferArgs(ciphertext, ctOffset, ctLength);
        Validator.checkBufferArgs(tag, tagOffset, tagLength());
        Validator.checkBufferArgs(plaintext, ptOffset, ctLength);
        if (state != State.NonceInitialized && state != State.ContextInitialized) {
            throw new IllegalStateException("Nonce must be initialized");
        }
        innerCipher.decrypt(ciphertext, ctOffset, ctLength, tag, tagOffset, plaintext, ptOffset);
        state = State.KeyInitialized;
    }

    private enum State {
        KeyInitialized, NonceInitialized, ContextInitialized
    }
}
