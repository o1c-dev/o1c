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

package dev.o1c.modern.ed25519;

import cafe.cryptography.curve25519.InvalidEncodingException;
import cafe.cryptography.ed25519.Ed25519ExpandedPrivateKey;
import cafe.cryptography.ed25519.Ed25519PrivateKey;
import cafe.cryptography.ed25519.Ed25519PublicKey;
import cafe.cryptography.ed25519.Ed25519Signature;
import dev.o1c.modern.chacha20.ChaCha20RandomBytesGenerator;
import dev.o1c.spi.InvalidSignatureException;
import dev.o1c.spi.PrivateKey;
import dev.o1c.spi.PublicKey;
import dev.o1c.spi.SignatureFactory;
import dev.o1c.spi.SigningKey;
import dev.o1c.spi.VerifyingKey;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public class Ed25519SignatureFactory implements SignatureFactory {
    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public @NotNull SigningKey generateKey() {
        return parsePrivateKey(ChaCha20RandomBytesGenerator.getInstance().generateBytes(keyLength()));
    }

    @Override
    public @NotNull SigningKey parseKey(@NotNull PrivateKey privateKey) {
        return new EdSigningKey(Ed25519PrivateKey.fromByteArray(privateKey.key()));
    }

    @Override
    public @NotNull VerifyingKey parseKey(@NotNull PublicKey publicKey) {
        try {
            return new EdVerifyingKey(Ed25519PublicKey.fromByteArray(publicKey.key()));
        } catch (InvalidEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public @NotNull SigningKey parsePrivateKey(byte @NotNull [] key) {
        return new EdSigningKey(Ed25519PrivateKey.fromByteArray(key));
    }

    @Override
    public @NotNull VerifyingKey parsePublicKey(byte @NotNull [] key) {
        try {
            return new EdVerifyingKey(Ed25519PublicKey.fromByteArray(key));
        } catch (InvalidEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static class EdVerifyingKey implements VerifyingKey {
        private final Ed25519PublicKey key;

        private EdVerifyingKey(Ed25519PublicKey key) {
            this.key = key;
        }

        @Override
        public int signatureLength() {
            return 64;
        }

        @Override
        public void verify(byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset) {
            byte[] signatureBuf = Arrays.copyOfRange(signature, sigOffset, sigOffset + signatureLength());
            Ed25519Signature sig = Ed25519Signature.fromByteArray(signatureBuf);
            if (!key.verify(message, offset, length, sig)) {
                throw new InvalidSignatureException("Signature mismatch");
            }
        }
    }

    private static class EdSigningKey extends EdVerifyingKey implements SigningKey {
        private final Ed25519ExpandedPrivateKey key;

        private EdSigningKey(Ed25519PrivateKey key) {
            super(key.derivePublic());
            this.key = key.expand();
        }

        @Override
        public void sign(byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset) {
            Ed25519Signature sig = key.sign(message, offset, length, super.key);
            System.arraycopy(sig.toByteArray(), 0, signature, sigOffset, signatureLength());
        }
    }
}
