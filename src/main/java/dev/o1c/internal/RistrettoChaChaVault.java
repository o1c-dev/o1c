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

package dev.o1c.internal;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.InvalidEncodingException;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.RistrettoGeneratorTable;
import cafe.cryptography.curve25519.Scalar;
import dev.o1c.impl.blake3.Blake3RandomBytesGenerator;
import dev.o1c.impl.chacha20.XChaCha20Poly1305CipherKeyFactory;
import dev.o1c.modern.blake2.Blake2bHashFactory;
import dev.o1c.spi.CipherKey;
import dev.o1c.spi.CipherKeyFactory;
import dev.o1c.spi.CryptoHash;
import dev.o1c.spi.HashFactory;
import dev.o1c.spi.InvalidSealException;
import dev.o1c.spi.InvalidSignatureException;
import dev.o1c.spi.Vault;
import dev.o1c.util.ByteOps;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.spec.EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;

public class RistrettoChaChaVault implements Vault {
    private static final int ASYMMETRIC_KEY_SIZE = 32;
    private static final int SYMMETRIC_KEY_SIZE = 32;
    private static final int AUTHENTICATION_TAG_SIZE = 16;
    private static final int NONCE_SIZE = 24;
    private static final int SIGNATURE_SIZE = 64;
    private static final int MAX_BYTES_PER_SEAL = 1 << 30;
    private static final byte[] SHARED_KEY = "shared_key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SIGN_KEY = "sign_key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] NONCE = "nonce".getBytes(StandardCharsets.UTF_8);
    private static final String ALGORITHM = "Ristretto255";
    private static final RistrettoGeneratorTable BASE_GENERATOR = Constants.RISTRETTO_GENERATOR_TABLE;

    private final CipherKeyFactory cipherKeyFactory = new XChaCha20Poly1305CipherKeyFactory();
    private final HashFactory hashFactory = new Blake2bHashFactory();

    @Override
    public KeyPair generateKeyPair() {
        byte[] key = Blake3RandomBytesGenerator.getInstance().generateBytes(ASYMMETRIC_KEY_SIZE);
        KeyPair keyPair = parsePrivateKey(key);
        ByteOps.overwriteWithZeroes(key);
        return keyPair;
    }

    KeyPair parsePrivateKey(byte[] key) {
        PrivateKey privateKey = new PrivateKey(Scalar.fromBytesModOrder(key));
        PublicKey publicKey = new PublicKey(BASE_GENERATOR.multiply(privateKey.key));
        return new KeyPair(publicKey, privateKey);
    }

    @Override
    public SecretKey generateSecretKey() {
        byte[] key = Blake3RandomBytesGenerator.getInstance().generateBytes(SYMMETRIC_KEY_SIZE);
        SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);
        ByteOps.overwriteWithZeroes(key);
        return secretKey;
    }

    @Override
    public byte[] seal(SecretKey secretKey, byte[] context, byte[] data) {
        Objects.requireNonNull(secretKey);
        Objects.requireNonNull(context);
        Objects.requireNonNull(data);
        CipherKey key = cipherKeyFactory.parseKey(secretKey.getEncoded());
        byte[] nonce = Blake3RandomBytesGenerator.getInstance().generateBytes(nonceLength());
        byte[] sealed = Arrays.copyOf(nonce, nonceLength() + data.length + tagLength());
        key.encrypt(nonce, context, data, 0, data.length, sealed, nonceLength(), sealed, sealed.length - tagLength());
        return sealed;
    }

    @Override
    public byte[] unseal(SecretKey secretKey, byte[] context, byte[] sealedData) {
        Objects.requireNonNull(secretKey);
        Objects.requireNonNull(context);
        Objects.requireNonNull(sealedData);
        int msgLen = sealedData.length - nonceLength() - tagLength();
        if (msgLen < 0) {
            throw new InvalidSealException("Missing metadata");
        }
        CipherKey key = cipherKeyFactory.parseKey(secretKey.getEncoded());
        byte[] nonce = Arrays.copyOf(sealedData, nonceLength());
        byte[] data = new byte[msgLen];
        key.decrypt(nonce, context, sealedData, nonceLength(), data.length, sealedData, sealedData.length - key.tagLength(), data, 0);
        return data;
    }

    @Override
    public byte[] wrap(
            java.security.PrivateKey senderKey, byte[] senderId, java.security.PublicKey recipientKey, byte[] recipientId,
            byte[] context, byte[] data) {
        checkArgs(senderId, recipientId, context);
        Objects.requireNonNull(data);
        if (data.length > MAX_BYTES_PER_SEAL) {
            throw new IllegalArgumentException("Can only seal up to 1 GB of data per invocation");
        }
        if (!(senderKey instanceof PrivateKey && recipientKey instanceof PublicKey)) {
            throw new IllegalArgumentException("Unsupported key types");
        }
        Scalar sender = ((PrivateKey) senderKey).key;
        RistrettoElement recipient = ((PublicKey) recipientKey).key;

        Consumer<CryptoHash> absorbContextInfo = hash -> {
            hash.update((byte) senderId.length);
            hash.update(senderId);
            hash.update((byte) recipientId.length);
            hash.update(recipientId);
            hash.update((byte) context.length);
            hash.update(context);
        };
        CryptoHash hash = hashFactory.init(ASYMMETRIC_KEY_SIZE * 2);
        hash.update(NONCE);
        hash.update(senderKey.getEncoded());
        hash.update(recipientKey.getEncoded());
        byte[] noise = Blake3RandomBytesGenerator.getInstance().generateBytes(32);
        hash.update(noise);
        hash.update(data);
        Scalar ephemeralPrivateKey = Scalar.fromBytesModOrderWide(hash.finish());
        RistrettoElement ephemeralPublicKey = BASE_GENERATOR.multiply(ephemeralPrivateKey);
        byte[] r = ephemeralPublicKey.compress().toByteArray(); // first half of signature

        RistrettoElement kp = recipient.multiply(Scalar.fromBits(r).multiplyAndAdd(sender, ephemeralPrivateKey));
        byte[] k = kp.compress().toByteArray();
        hash = hashFactory.init(SYMMETRIC_KEY_SIZE);
        hash.update(SHARED_KEY);
        hash.update(k);
        absorbContextInfo.accept(hash);
        byte[] sharedKey = hash.finish();
        CipherKey key = cipherKeyFactory.parseKey(sharedKey);

        hash = hashFactory.init(signatureLength());
        hash.update(SIGN_KEY);
        hash.update(r);
        absorbContextInfo.accept(hash);
        byte[] nonce = Blake3RandomBytesGenerator.getInstance().generateBytes(nonceLength());
        int ctLen = nonceLength() + data.length + tagLength();
        byte[] wrapped = Arrays.copyOf(nonce, ctLen + signatureLength());
        key.encrypt(nonce, context, data, 0, data.length, wrapped, nonceLength(), wrapped, nonceLength() + data.length);
        hash.update(wrapped, nonceLength(), data.length);
        byte[] s =
                Scalar.fromBytesModOrderWide(hash.finish()).multiply(sender).subtract(ephemeralPrivateKey).toByteArray();
        System.arraycopy(r, 0, wrapped, ctLen, r.length);
        System.arraycopy(s, 0, wrapped, ctLen + r.length, s.length);
        return wrapped;
    }

    @Override
    public byte[] unwrap(
            java.security.PublicKey senderKey, byte[] senderId, java.security.PrivateKey recipientKey, byte[] recipientId,
            byte[] context, byte[] wrappedData) {
        checkArgs(senderId, recipientId, context);
        Objects.requireNonNull(wrappedData);
        if (!(senderKey instanceof PublicKey && recipientKey instanceof PrivateKey)) {
            throw new IllegalArgumentException("Unsupported key types");
        }
        int msgLen = wrappedData.length - nonceLength() - tagLength() - signatureLength();
        if (msgLen < 0) {
            throw new InvalidSealException("Sealed data is missing metadata");
        }
        RistrettoElement sender = ((PublicKey) senderKey).key;
        Scalar recipient = ((PrivateKey) recipientKey).key;
        byte[] r =
                Arrays.copyOfRange(wrappedData, wrappedData.length - signatureLength(), wrappedData.length - 32);
        byte[] s = Arrays.copyOfRange(wrappedData, wrappedData.length - 32, wrappedData.length);
        Scalar reduced = Scalar.fromBits(r);
        RistrettoElement publicSigningKey;
        try {
            publicSigningKey = new CompressedRistretto(r).decompress();
        } catch (InvalidEncodingException e) {
            throw new InvalidSealException(e);
        }

        byte[] k = sender.multiply(reduced).add(publicSigningKey).multiply(recipient).compress().toByteArray();
        CryptoHash hash = hashFactory.init(cipherKeyFactory.keyLength());
        hash.update(SHARED_KEY);
        hash.update(k);
        hash.update((byte) senderId.length);
        hash.update(senderId);
        hash.update((byte) recipientId.length);
        hash.update(recipientId);
        hash.update((byte) context.length);
        hash.update(context);
        byte[] sharedKey = hash.finish();
        CipherKey key = cipherKeyFactory.parseKey(sharedKey);

        byte[] nonce = Arrays.copyOf(wrappedData, nonceLength());
        hash = hashFactory.init(signatureLength());
        hash.update(SIGN_KEY);
        hash.update(r);
        hash.update((byte) senderId.length);
        hash.update(senderId);
        hash.update((byte) recipientId.length);
        hash.update(recipientId);
        hash.update((byte) context.length);
        hash.update(context);
        hash.update(wrappedData, nonceLength(), msgLen);
        if (sender.multiply(Scalar.fromBytesModOrderWide(hash.finish()))
                .ctEquals(BASE_GENERATOR.multiply(Scalar.fromCanonicalBytes(s)).add(publicSigningKey)) != 1) {
            throw new InvalidSignatureException("Bad signature");
        }
        byte[] data = new byte[msgLen];
        key.decrypt(nonce, context, wrappedData, nonce.length, msgLen, wrappedData, nonce.length + msgLen, data, 0);
        return data;
    }

    @Override
    public int tagLength() {
        return AUTHENTICATION_TAG_SIZE;
    }

    @Override
    public int nonceLength() {
        return NONCE_SIZE;
    }

    @Override
    public int signatureLength() {
        return SIGNATURE_SIZE;
    }

    private static void checkArgs(byte[] senderId, byte[] recipientId, byte[] context) {
        Objects.requireNonNull(senderId);
        Objects.requireNonNull(recipientId);
        Objects.requireNonNull(context);
        if (senderId.length > 255) {
            throw new IllegalArgumentException("Sender id can only be up to 255 bytes");
        }
        if (recipientId.length > 255) {
            throw new IllegalArgumentException("Recipient id can only be up to 255 bytes");
        }
        if (context.length > 255) {
            throw new IllegalArgumentException("Context data can only be up to 255 bytes");
        }
    }

    private static class PrivateKey extends EncodedKeySpec implements java.security.PrivateKey {
        private final Scalar key;

        public PrivateKey(Scalar key) {
            super(key.toByteArray());
            this.key = key;
        }

        @Override
        public String getAlgorithm() {
            return ALGORITHM;
        }

        @Override
        public String getFormat() {
            return "RAW";
        }
    }

    private static class PublicKey extends EncodedKeySpec implements java.security.PublicKey {
        private final RistrettoElement key;

        private PublicKey(RistrettoElement key) {
            super(key.compress().toByteArray());
            this.key = key;
        }

        @Override
        public String getAlgorithm() {
            return ALGORITHM;
        }

        @Override
        public String getFormat() {
            return "RAW";
        }
    }
}
