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

package dev.o1c.spi;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.InvalidEncodingException;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.RistrettoGeneratorTable;
import cafe.cryptography.curve25519.Scalar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

public class Vault {
    private final SecureRandom secureRandom;

    public Vault() {
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
    }

    public KeyPair generateKeyPair() {
        byte[] key = new byte[KEY_SIZE];
        secureRandom.nextBytes(key);
        return parsePrivateKey(key);
    }

    KeyPair parsePrivateKey(byte[] key) {
        VaultPrivateKey privateKey = new VaultPrivateKey(Scalar.fromBytesModOrder(key));
        VaultPublicKey publicKey = privateKey.generatePublicKey();
        return new KeyPair(publicKey, privateKey);
    }

    public byte[] seal(
            PrivateKey senderKey, byte[] senderId, PublicKey recipientKey, byte[] recipientId, byte[] context, byte[] data) {
        if (!(senderKey instanceof VaultPrivateKey) || !(recipientKey instanceof VaultPublicKey)) {
            throw new IllegalArgumentException("Only vault key pairs are allowed");
        }
        Objects.requireNonNull(senderId);
        Objects.requireNonNull(recipientId);
        Objects.requireNonNull(context);
        Objects.requireNonNull(data);
        if (senderId.length > 255) {
            throw new IllegalArgumentException("Sender id can only be up to 255 bytes");
        }
        if (recipientId.length > 255) {
            throw new IllegalArgumentException("Recipient id can only be up to 255 bytes");
        }
        if (context.length > 255) {
            throw new IllegalArgumentException("Context data can only be up to 255 bytes");
        }
        if (data.length > MAX_BYTES_PER_SEAL) {
            throw new IllegalArgumentException("Can only seal up to 1 GB of data per invocation");
        }
        return seal((VaultPrivateKey) senderKey, senderId, (VaultPublicKey) recipientKey, recipientId, context, data);
    }

    private byte[] seal(
            VaultPrivateKey sender, byte[] senderId, VaultPublicKey recipient, byte[] recipientId, byte[] context,
            byte[] data) {
        MessageDigest digest = getFullDigest();
        digest.update(NONCE);
        digest.update(sender.getEncoded());
        digest.update(recipient.getEncoded());
        byte[] noise = new byte[32];
        secureRandom.nextBytes(noise);
        digest.update(noise);
        digest.update(data);
        byte[] nonce = digest.digest();
        Scalar ephemeralPrivateKey = Scalar.fromBytesModOrderWide(nonce);
        RistrettoElement ephemeralPublicKey = Constants.RISTRETTO_GENERATOR_TABLE.multiply(ephemeralPrivateKey);
        byte[] rBuf = ephemeralPublicKey.compress().toByteArray();
        RistrettoElement kp =
                recipient.table.multiply(Scalar.fromBits(rBuf).multiplyAndAdd(sender.value, ephemeralPrivateKey));
        byte[] k = kp.compress().toByteArray();

        digest = getReducedDigest();
        digest.update(SHARED_KEY);
        digest.update(k);
        digestVariableLengthBuffer(digest, senderId);
        digestVariableLengthBuffer(digest, recipientId);
        digestVariableLengthBuffer(digest, context);
        byte[] key = digest.digest();

        digest = getFullDigest();
        digest.update(SIGN_KEY);
        digest.update(rBuf);
        digestVariableLengthBuffer(digest, senderId);
        digestVariableLengthBuffer(digest, recipientId);
        digestVariableLengthBuffer(digest, context);

        byte[] iv = new byte[IV_SIZE];
        secureRandom.nextBytes(iv);
        Cipher cipher = XChaCha20Poly1305.cryptWith(true, key, iv);
        cipher.updateAAD(context);
        int ciphertextLength = IV_SIZE + cipher.getOutputSize(data.length);
        byte[] sealed = Arrays.copyOf(iv, ciphertextLength + SIG_SIZE);
        try {
            cipher.doFinal(data, 0, data.length, sealed, IV_SIZE);
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalStateException(e);
        }
        digest.update(sealed, IV_SIZE, data.length);
        Scalar challenge = Scalar.fromBytesModOrderWide(digest.digest());
        byte[] sBuf = challenge.multiply(sender.value).subtract(ephemeralPrivateKey).toByteArray();
        System.arraycopy(rBuf, 0, sealed, ciphertextLength, rBuf.length);
        System.arraycopy(sBuf, 0, sealed, ciphertextLength + rBuf.length, sBuf.length);
        return sealed;
    }

    public byte[] unseal(
            PublicKey senderKey, byte[] senderId, PrivateKey recipientKey, byte[] recipientId, byte[] context,
            byte[] sealedData) {
        if (!(senderKey instanceof VaultPublicKey) || !(recipientKey instanceof VaultPrivateKey)) {
            throw new IllegalArgumentException("Only vault key pairs are allowed");
        }
        Objects.requireNonNull(senderId);
        Objects.requireNonNull(recipientId);
        Objects.requireNonNull(context);
        Objects.requireNonNull(sealedData);
        if (senderId.length > 255) {
            throw new IllegalArgumentException("Sender id can only be up to 255 bytes");
        }
        if (recipientId.length > 255) {
            throw new IllegalArgumentException("Recipient id can only be up to 255 bytes");
        }
        if (context.length > 255) {
            throw new IllegalArgumentException("Context data can only be up to 255 bytes");
        }
        if (sealedData.length < IV_SIZE + TAG_SIZE + SIG_SIZE) {
            throw new IllegalArgumentException("Sealed data is missing metadata");
        }
        return unseal((VaultPublicKey) senderKey, senderId, (VaultPrivateKey) recipientKey, recipientId, context, sealedData);
    }

    private byte[] unseal(
            VaultPublicKey sender, byte[] senderId, VaultPrivateKey recipient, byte[] recipientId, byte[] context,
            byte[] sealed) {
        byte[] rBuf = Arrays.copyOfRange(sealed, sealed.length - SIG_SIZE, sealed.length - KEY_SIZE);
        byte[] sBuf = Arrays.copyOfRange(sealed, sealed.length - KEY_SIZE, sealed.length);

        RistrettoElement r;
        try {
            r = new CompressedRistretto(rBuf).decompress();
        } catch (InvalidEncodingException e) {
            throw new InvalidSealException(e);
        }
        Scalar rs = Scalar.fromBits(rBuf);
        byte[] k = sender.table.multiply(rs).add(r).multiply(recipient.value).compress().toByteArray();
        MessageDigest digest = getReducedDigest();
        digest.update(SHARED_KEY);
        digest.update(k);
        digestVariableLengthBuffer(digest, senderId);
        digestVariableLengthBuffer(digest, recipientId);
        digestVariableLengthBuffer(digest, context);
        byte[] key = digest.digest();
        byte[] iv = Arrays.copyOf(sealed, IV_SIZE);

        digest = getFullDigest();
        digest.update(SIGN_KEY);
        digest.update(rBuf);
        digestVariableLengthBuffer(digest, senderId);
        digestVariableLengthBuffer(digest, recipientId);
        digestVariableLengthBuffer(digest, context);
        int msgLen = sealed.length - SIG_SIZE - IV_SIZE - TAG_SIZE;
        digest.update(sealed, IV_SIZE, msgLen);
        Scalar s = Scalar.fromCanonicalBytes(sBuf);
        RistrettoElement expected = Constants.RISTRETTO_GENERATOR_TABLE.multiply(s).add(r);
        RistrettoElement actual = sender.table.multiply(Scalar.fromBytesModOrderWide(digest.digest()));
        if (expected.ctEquals(actual) == 0) {
            throw new InvalidSealException("Signature mismatch");
        }
        Cipher cipher = XChaCha20Poly1305.cryptWith(false, key, iv);
        cipher.updateAAD(context);
        try {
            return cipher.doFinal(sealed, IV_SIZE, msgLen + TAG_SIZE);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException(e);
        } catch (BadPaddingException e) {
            throw new InvalidSealException(e);
        }
    }

    private static final int KEY_SIZE = 32;
    private static final int SIG_SIZE = 64;
    private static final int TAG_SIZE = 16;
    private static final int IV_SIZE = 24;
    private static final int MAX_BYTES_PER_SEAL = 1 << 30;
    // libsodium uses Blake2b by default, though Blake3 is now available, but the Java libraries are pretty meh
    private static final String FULL_DIGEST_ALGORITHM = "BLAKE2B-512";
    private static final String REDUCED_DIGEST_ALGORITHM = "BLAKE2B-256";
    private static final String ALGORITHM = "SignCrypt25519";
    private static final byte[] SHARED_KEY = "shared_key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SIGN_KEY = "sign_key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] NONCE = "nonce".getBytes(StandardCharsets.UTF_8);

    private static MessageDigest getFullDigest() {
        try {
            return MessageDigest.getInstance(FULL_DIGEST_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
    }

    private static MessageDigest getReducedDigest() {
        try {
            return MessageDigest.getInstance(REDUCED_DIGEST_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
    }

    private static void digestVariableLengthBuffer(MessageDigest digest, byte[] buf) {
        digest.update((byte) (buf.length & 0xff));
        digest.update(buf);
    }

    private static class VaultPrivateKey implements PrivateKey {
        private final Scalar value;

        private VaultPrivateKey(Scalar value) {
            this.value = value;
        }

        @Override
        public String getAlgorithm() {
            return ALGORITHM;
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            return value.toByteArray();
        }

        VaultPublicKey generatePublicKey() {
            return new VaultPublicKey(Constants.RISTRETTO_GENERATOR_TABLE.multiply(value));
        }
    }

    private static class VaultPublicKey implements PublicKey {
        private final RistrettoElement value;
        private transient RistrettoGeneratorTable table;

        private VaultPublicKey(RistrettoElement value) {
            this.value = value;
            table = new RistrettoGeneratorTable(value);
        }

        private Object readResolve() {
            table = new RistrettoGeneratorTable(value);
            return this;
        }

        @Override
        public String getAlgorithm() {
            return ALGORITHM;
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            return value.compress().toByteArray();
        }
    }
}
