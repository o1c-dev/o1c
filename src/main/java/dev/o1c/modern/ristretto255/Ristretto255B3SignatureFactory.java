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

package dev.o1c.modern.ristretto255;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.InvalidEncodingException;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.Scalar;
import dev.o1c.modern.blake3.Blake3HashFactory;
import dev.o1c.modern.blake3.Blake3RandomBytesGenerator;
import dev.o1c.spi.CryptoHash;
import dev.o1c.spi.HashFactory;
import dev.o1c.spi.InvalidKeyException;
import dev.o1c.spi.InvalidSignatureException;
import dev.o1c.spi.SignatureFactory;
import dev.o1c.spi.SigningKey;
import dev.o1c.spi.VerifyingKey;
import org.jetbrains.annotations.NotNull;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.util.Arrays;

/**
 * Provides an EdDSA signature factory for a Ristretto255/Blake3 parameterized variant of Ed25519. Replacing the traditional
 * point compression with the Ristretto variant allows for a unified signature, asymmetric encryption, and signcryption system.
 * Replacing the use of SHA-2 with Blake3 improves hashing performance (the primary driver of a signature computation for
 * larger messages) with equivalent or better security.
 */
public class Ristretto255B3SignatureFactory implements SignatureFactory {
    private final HashFactory hashFactory = new Blake3HashFactory();

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public @NotNull SigningKey generateSigningKey() {
        return parseSigningKey(Blake3RandomBytesGenerator.getInstance().generateBytes(keyLength()));
    }

    @Override
    public @NotNull SigningKey parseSigningKey(byte @NotNull [] key) {
        if (key.length != keyLength()) {
            throw new InvalidKeyException("Keys must be " + keyLength() + " bytes");
        }
        CryptoHash hash = hashFactory.init(key);
        byte[] h = new byte[2 * keyLength()];
        hash.finish(h);
        byte[] scalar = Arrays.copyOf(h, keyLength());
        byte[] prefix = Arrays.copyOfRange(h, keyLength(), h.length);
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        return new RistrettoSigningKey(Scalar.fromBits(scalar), prefix);
    }

    @Override
    public @NotNull VerifyingKey parseVerifyingKey(byte @NotNull [] key) {
        return new RistrettoVerifyingKey(new CompressedRistretto(key));
    }

    private class RistrettoVerifyingKey implements VerifyingKey {
        private final RistrettoElement publicKey;
        final CompressedRistretto encodedPublicKey;

        private RistrettoVerifyingKey(RistrettoElement publicKey) {
            this.publicKey = publicKey;
            this.encodedPublicKey = publicKey.compress();
        }

        private RistrettoVerifyingKey(CompressedRistretto encodedPublicKey) {
            this.encodedPublicKey = encodedPublicKey;
            try {
                this.publicKey = encodedPublicKey.decompress();
            } catch (InvalidEncodingException e) {
                throw new InvalidKeyException(e);
            }
        }

        @Override
        public int signatureLength() {
            return 64;
        }

        @Override
        public void verify(byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset) {
            if (offset + length > message.length) {
                throw new BufferUnderflowException();
            }
            if (sigOffset + signatureLength() > signature.length) {
                throw new BufferUnderflowException();
            }
            byte[] r = Arrays.copyOfRange(signature, sigOffset, sigOffset + 32);
            byte[] s = Arrays.copyOfRange(signature, sigOffset + 32, sigOffset + 64);
            RistrettoElement sB = Constants.RISTRETTO_GENERATOR_TABLE.multiply(Scalar.fromCanonicalBytes(s));
            CryptoHash hash = hashFactory.init();
            hash.update(r);
            hash.update(encodedPublicKey.toByteArray());
            hash.update(message, offset, length);
            byte[] digest = new byte[64];
            hash.finish(digest);
            Scalar k = Scalar.fromBytesModOrderWide(digest);
            RistrettoElement checkR = publicKey.negate().multiply(k).add(sB);
            try {
                if (!checkR.equals(new CompressedRistretto(r).decompress())) {
                    throw new InvalidSignatureException("Signature mismatch");
                }
            } catch (InvalidEncodingException e) {
                throw new InvalidSignatureException(e);
            }
        }
    }

    private class RistrettoSigningKey extends RistrettoVerifyingKey implements SigningKey {
        private final Scalar privateKey;
        private final CryptoHash challenge;

        private RistrettoSigningKey(Scalar privateKey, byte[] prefix) {
            super(Constants.RISTRETTO_GENERATOR_TABLE.multiply(privateKey));
            this.privateKey = privateKey;
            this.challenge = hashFactory.init(prefix);
        }

        @Override
        public void sign(byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset) {
            if (offset + length > message.length) {
                throw new BufferUnderflowException();
            }
            if (sigOffset + signatureLength() > signature.length) {
                throw new BufferOverflowException();
            }
            challenge.reset();
            challenge.update(message, offset, length);
            byte[] digest = new byte[64];
            challenge.finish(digest);
            Scalar r = Scalar.fromBytesModOrderWide(digest);
            byte[] R = Constants.RISTRETTO_GENERATOR_TABLE.multiply(r).compress().toByteArray();
            CryptoHash hash = hashFactory.init();
            hash.update(R);
            hash.update(encodedPublicKey.toByteArray());
            hash.update(message, offset, length);
            hash.finish(digest);
            Scalar k = Scalar.fromBytesModOrderWide(digest);
            Scalar s = k.multiplyAndAdd(privateKey, r);
            byte[] S = s.toByteArray();
            System.arraycopy(R, 0, signature, sigOffset, R.length);
            System.arraycopy(S, 0, signature, sigOffset + R.length, S.length);
        }
    }
}
