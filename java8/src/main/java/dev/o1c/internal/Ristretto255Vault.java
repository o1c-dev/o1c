/*
 * Copyright 2020 Matt Sicker
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dev.o1c.internal;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.InvalidEncodingException;
import dev.o1c.spi.InvalidProviderException;

import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Ristretto255Vault extends SignCryptVault<Ristretto255Vault.RistrettoScalar, Ristretto255Vault.RistrettoElement> {

    public Ristretto255Vault() {
        super(32, 32, 16, 24, 64);
    }

    @Override
    MessageDigest getDigest(int digestSize) {
        try {
            switch (digestSize) {
                case 32:
                    return MessageDigest.getInstance("BLAKE2B-256");

                case 64:
                    return MessageDigest.getInstance("BLAKE2B-512");

                default:
                    throw new IllegalArgumentException("Invalid digest size: " + digestSize);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
    }

    @Override
    Cipher initCipher(boolean forEncryption, byte[] key, byte[] iv) {
        return XChaCha20Poly1305.cryptWith(forEncryption, key, iv);
    }

    @Override
    RistrettoScalar fromBytesModOrder(byte[] buf) {
        switch (buf.length) {
            case 32:
                return new RistrettoScalar(cafe.cryptography.curve25519.Scalar.fromBytesModOrder(buf));

            case 64:
                return new RistrettoScalar(cafe.cryptography.curve25519.Scalar.fromBytesModOrderWide(buf));

            default:
                throw new IllegalArgumentException("Incorrect size");
        }
    }

    @Override
    RistrettoScalar fromBits(byte[] buf) {
        return new RistrettoScalar(cafe.cryptography.curve25519.Scalar.fromBits(buf));
    }

    @Override
    RistrettoScalar fromCanonical(byte[] repr) {
        return new RistrettoScalar(cafe.cryptography.curve25519.Scalar.fromCanonicalBytes(repr));
    }

    @Override
    RistrettoElement baseGeneratorProduct(RistrettoScalar scalar) {
        return new RistrettoElement(Constants.RISTRETTO_GENERATOR_TABLE.multiply(scalar.scalar));
    }

    @Override
    RistrettoElement fromCompressed(byte[] buf) {
        try {
            return new RistrettoElement(new CompressedRistretto(buf).decompress());
        } catch (InvalidEncodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static class RistrettoScalar implements GroupOperations.Scalar<RistrettoScalar> {
        private final cafe.cryptography.curve25519.Scalar scalar;

        RistrettoScalar(cafe.cryptography.curve25519.Scalar scalar) {
            this.scalar = scalar;
        }

        @Override
        public byte[] toByteArray() {
            return scalar.toByteArray();
        }

        @Override
        public RistrettoScalar multiplyAndAdd(RistrettoScalar multiplicand, RistrettoScalar addend) {
            return new RistrettoScalar(scalar.multiplyAndAdd(multiplicand.scalar, addend.scalar));
        }

        @Override
        public RistrettoScalar multiplyAndSubtract(
                RistrettoScalar multiplicand, RistrettoScalar difference) {
            return new RistrettoScalar(scalar.multiply(multiplicand.scalar).subtract(difference.scalar));
        }
    }

    static class RistrettoElement implements GroupOperations.Element<RistrettoScalar, RistrettoElement> {
        private final cafe.cryptography.curve25519.RistrettoElement element;

        RistrettoElement(cafe.cryptography.curve25519.RistrettoElement element) {
            this.element = element;
        }

        @Override
        public byte[] toByteArray() {
            return element.compress().toByteArray();
        }

        @Override
        public RistrettoElement add(RistrettoElement addend) {
            return new RistrettoElement(element.add(addend.element));
        }

        @Override
        public RistrettoElement multiply(RistrettoScalar multiplicand) {
            return new RistrettoElement(element.multiply(multiplicand.scalar));
        }

        @Override
        public boolean isEqual(RistrettoElement element) {
            return this.element.ctEquals(element.element) == 1;
        }
    }
}
