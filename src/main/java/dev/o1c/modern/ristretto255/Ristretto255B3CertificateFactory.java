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
import dev.o1c.spi.Certificate;
import dev.o1c.spi.CertificateFactory;
import dev.o1c.spi.CryptoHash;
import dev.o1c.spi.HashFactory;
import dev.o1c.spi.InvalidKeyException;
import dev.o1c.spi.InvalidSignatureException;
import dev.o1c.spi.PrivateKey;
import org.jetbrains.annotations.NotNull;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.util.Arrays;

public class Ristretto255B3CertificateFactory implements CertificateFactory {
    private final HashFactory blake3 = new Blake3HashFactory();

    @Override
    public @NotNull Certificate parsePublicKey(byte @NotNull [] publicKey) {
        return new Ristretto255B3Certificate(new CompressedRistretto(publicKey));
    }

    @Override
    public @NotNull PrivateKey parsePrivateKey(byte @NotNull [] privateKey) {
        if (privateKey.length != 32) {
            throw new InvalidKeyException("Keys must be 32 bytes");
        }
        byte[] hash = new byte[64];
        blake3.init(privateKey).finish(hash);
        byte[] lower = Arrays.copyOf(hash, 32);
        byte[] upper = Arrays.copyOfRange(hash, 32, 64);
        lower[0] &= 248;
        lower[31] &= 127;
        lower[31] |= 64;
        Scalar scalar = Scalar.fromBits(lower);
        CryptoHash challenge = blake3.init(upper);
        return new Ristretto255B3PrivateKey(scalar, challenge);
    }

    @Override
    public @NotNull PrivateKey generateKey() {
        return parsePrivateKey(Blake3RandomBytesGenerator.getInstance().generateBytes(32));
    }

    private class Ristretto255B3Certificate implements Certificate {
        private final byte[] id;
        private final RistrettoElement element;
        private final RistrettoElement negatedElement;
        private final CompressedRistretto publicKey;

        Ristretto255B3Certificate(byte @NotNull [] id, @NotNull RistrettoElement element) {
            this.id = id.clone();
            this.element = element;
            negatedElement = element.negate();
            publicKey = element.compress();
        }

        Ristretto255B3Certificate(byte @NotNull [] id, @NotNull CompressedRistretto publicKey) {
            this.id = id.clone();
            this.publicKey = publicKey;
            try {
                element = publicKey.decompress();
            } catch (InvalidEncodingException e) {
                throw new InvalidKeyException(e);
            }
            negatedElement = element.negate();
        }

        Ristretto255B3Certificate(@NotNull RistrettoElement element) {
            this.element = element;
            negatedElement = element.negate();
            publicKey = element.compress();
            id = publicKey.toByteArray();
        }

        Ristretto255B3Certificate(@NotNull CompressedRistretto publicKey) {
            this.publicKey = publicKey;
            id = publicKey.toByteArray();
            try {
                element = publicKey.decompress();
            } catch (InvalidEncodingException e) {
                throw new InvalidKeyException(e);
            }
            negatedElement = element.negate();
        }

        @Override
        public byte @NotNull [] id() {
            return id.clone();
        }

        @Override
        public byte @NotNull [] publicKey() {
            return publicKey.toByteArray().clone();
        }

        @Override
        public int keyLength() {
            return 32;
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
            RistrettoElement R;
            try {
                R = new CompressedRistretto(r).decompress();
            } catch (InvalidEncodingException e) {
                throw new InvalidSignatureException(e);
            }
            byte[] s = Arrays.copyOfRange(signature, sigOffset + 32, sigOffset + 64);
            RistrettoElement S = Constants.RISTRETTO_GENERATOR_TABLE.multiply(Scalar.fromCanonicalBytes(s));

            CryptoHash hash = blake3.init(64);
            hash.update(r);
            hash.update(publicKey.toByteArray());
            hash.update(message, offset, length);
            Scalar k = Scalar.fromBytesModOrderWide(hash.finish());
            if (!R.equals(negatedElement.multiply(k).add(S))) {
                throw new InvalidSignatureException("Signature mismatch");
            }
        }

        @NotNull RistrettoElement element() {
            return element;
        }
    }

    private class Ristretto255B3PrivateKey extends Ristretto255B3Certificate implements PrivateKey {
        private final Scalar scalar;
        private final CryptoHash challenge;

        Ristretto255B3PrivateKey(byte @NotNull [] id, @NotNull Scalar scalar, @NotNull CryptoHash challenge) {
            super(id, Constants.RISTRETTO_GENERATOR_TABLE.multiply(scalar));
            this.scalar = scalar;
            this.challenge = challenge;
        }

        Ristretto255B3PrivateKey(@NotNull Scalar scalar, @NotNull CryptoHash challenge) {
            super(Constants.RISTRETTO_GENERATOR_TABLE.multiply(scalar));
            this.scalar = scalar;
            this.challenge = challenge;
        }

        @Override
        public void sign(
                byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset) {
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
            CryptoHash hash = blake3.init(64);
            hash.update(R);
            hash.update(publicKey());
            hash.update(message, offset, length);
            Scalar k = Scalar.fromBytesModOrderWide(hash.finish());
            Scalar s = k.multiplyAndAdd(scalar, r);
            byte[] S = s.toByteArray();
            System.arraycopy(R, 0, signature, sigOffset, R.length);
            System.arraycopy(S, 0, signature, sigOffset + R.length, S.length);
        }

        @Override
        public byte @NotNull [] sharedSecret(@NotNull Certificate peer) {
            if (peer instanceof Ristretto255B3Certificate) {
                RistrettoElement peerElement = ((Ristretto255B3Certificate) peer).element();
                return peerElement.multiply(scalar).compress().toByteArray();
            }
            throw new UnsupportedOperationException("Invalid certificate type: " + peer.getClass());
        }
    }
}
