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

import dev.o1c.spi.InvalidProviderException;
import dev.o1c.spi.InvalidSealException;
import dev.o1c.spi.Vault;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

abstract class SignCryptVault<S extends GroupOperations.Scalar<S>, E extends GroupOperations.Element<S, E>> implements Vault {
    private static final int MAX_BYTES_PER_SEAL = 1 << 30;
    private static final byte[] SHARED_KEY = "shared_key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SIGN_KEY = "sign_key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] NONCE = "nonce".getBytes(StandardCharsets.UTF_8);

    final SecureRandom secureRandom;
    final int asymmetricKeySize;
    final int symmetricKeySize;
    final int tagSize;
    final int nonceSize;
    final int sigSize;

    SignCryptVault(int asymmetricKeySize, int symmetricKeySize, int tagSize, int nonceSize, int sigSize) {
        this.asymmetricKeySize = asymmetricKeySize;
        this.symmetricKeySize = symmetricKeySize;
        this.tagSize = tagSize;
        this.nonceSize = nonceSize;
        this.sigSize = sigSize;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
    }

    abstract MessageDigest getDigest(int digestSize);

    abstract Cipher initCipher(boolean forEncryption, byte[] key, byte[] iv);

    abstract S fromBytesModOrder(byte[] buf);

    abstract S fromBits(byte[] buf);

    abstract S fromCanonical(byte[] repr);

    abstract E baseGeneratorProduct(S scalar);

    abstract E fromCompressed(byte[] buf);

    @Override
    public KeyPair generateKeyPair() {
        byte[] key = new byte[asymmetricKeySize];
        secureRandom.nextBytes(key);
        return parsePrivateKey(key);
    }

    KeyPair parsePrivateKey(byte[] key) {
        S sk = fromBytesModOrder(key);
        E pk = baseGeneratorProduct(sk);
        return new KeyPair(new PKey(pk.toByteArray()), new SKey(sk.toByteArray()));
    }

    @Override
    public SecretKey generateSecretKey() {
        byte[] key = new byte[symmetricKeySize];
        secureRandom.nextBytes(key);
        return new SecretKeySpec(key, "SignCrypt");
    }

    @Override
    public byte[] seal(SecretKey secretKey, byte[] context, byte[] data) {
        Objects.requireNonNull(secretKey);
        Objects.requireNonNull(context);
        Objects.requireNonNull(data);
        byte[] iv = new byte[nonceSize];
        secureRandom.nextBytes(iv);
        Cipher cipher = initCipher(true, secretKey.getEncoded(), iv);
        cipher.updateAAD(context);
        byte[] sealed = Arrays.copyOf(iv, nonceSize + cipher.getOutputSize(data.length));
        try {
            cipher.doFinal(data, 0, data.length, sealed, nonceSize);
        } catch (IllegalBlockSizeException | ShortBufferException e) {
            throw new IllegalStateException(e);
        } catch (BadPaddingException e) {
            throw new InvalidSealException(e);
        }
        return sealed;
    }

    @Override
    public byte[] unseal(SecretKey secretKey, byte[] context, byte[] sealedData) {
        Objects.requireNonNull(secretKey);
        Objects.requireNonNull(context);
        Objects.requireNonNull(sealedData);
        int msgLen = sealedData.length - nonceSize - tagSize;
        if (msgLen < 0) {
            throw new InvalidSealException("Missing metadata");
        }
        Cipher cipher = initCipher(false, secretKey.getEncoded(), Arrays.copyOf(sealedData, nonceSize));
        cipher.updateAAD(context);
        try {
            return cipher.doFinal(sealedData, nonceSize, msgLen + tagSize);
        } catch (BadPaddingException e) {
            throw new InvalidSealException(e);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public byte[] seal(
            PrivateKey senderKey, byte[] senderId, PublicKey recipientKey, byte[] recipientId, byte[] context, byte[] data) {
        Objects.requireNonNull(senderKey);
        Objects.requireNonNull(recipientKey);
        Objects.requireNonNull(data);
        checkArgs(senderId, recipientId, context);
        if (data.length > MAX_BYTES_PER_SEAL) {
            throw new IllegalArgumentException("Can only seal up to 1 GB of data per invocation");
        }
        S sender = fromCanonical(senderKey.getEncoded());
        E recipient = fromCompressed(recipientKey.getEncoded());

        MessageDigest digest = getDigest(asymmetricKeySize * 2);
        digest.update(NONCE);
        digest.update(sender.toByteArray());
        digest.update(recipient.toByteArray());
        byte[] noise = new byte[32];
        secureRandom.nextBytes(noise);
        digest.update(noise);
        digest.update(data);
        S ephemeralPrivateKey = fromBytesModOrder(digest.digest());
        byte[] ephemeralPublicKey = baseGeneratorProduct(ephemeralPrivateKey).toByteArray();
        byte[] k = recipient.multiply(fromBits(ephemeralPublicKey).multiplyAndAdd(sender, ephemeralPrivateKey)).toByteArray();

        digest = getDigest(symmetricKeySize);
        digest.update(SHARED_KEY);
        digest.update(k);
        digestVariableLengthBuffers(digest, senderId, recipientId, context);
        byte[] key = digest.digest();

        digest = getDigest(sigSize);
        digest.update(SIGN_KEY);
        digest.update(ephemeralPublicKey);
        digestVariableLengthBuffers(digest, senderId, recipientId, context);
        byte[] iv = new byte[nonceSize];
        secureRandom.nextBytes(iv);
        Cipher cipher = initCipher(true, key, iv);
        cipher.updateAAD(context);
        int ciphertextLength = nonceSize + cipher.getOutputSize(data.length);
        byte[] sealed = Arrays.copyOf(iv, ciphertextLength + sigSize);
        try {
            cipher.doFinal(data, 0, data.length, sealed, nonceSize);
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalStateException(e);
        }
        digest.update(sealed, nonceSize, data.length);
        byte[] s = fromBytesModOrder(digest.digest()).multiplyAndSubtract(sender, ephemeralPrivateKey).toByteArray();
        System.arraycopy(ephemeralPublicKey, 0, sealed, ciphertextLength, ephemeralPublicKey.length);
        System.arraycopy(s, 0, sealed, ciphertextLength + ephemeralPublicKey.length, s.length);
        return sealed;
    }

    @Override
    public byte[] unseal(
            PublicKey senderKey, byte[] senderId, PrivateKey recipientKey, byte[] recipientId, byte[] context,
            byte[] sealedData) {
        Objects.requireNonNull(senderKey);
        Objects.requireNonNull(recipientKey);
        Objects.requireNonNull(sealedData);
        checkArgs(senderId, recipientId, context);
        int msgLen = sealedData.length - nonceSize - tagSize - sigSize;
        if (msgLen < 0) {
            throw new InvalidSealException("Sealed data is missing metadata");
        }
        E sender = fromCompressed(senderKey.getEncoded());
        S recipient = fromCanonical(recipientKey.getEncoded());
        int rOffset = sealedData.length - sigSize;
        int sOffset = sealedData.length - (sigSize >> 1);
        byte[] r = Arrays.copyOfRange(sealedData, rOffset, sOffset);
        E R = fromCompressed(r);
        byte[] s = Arrays.copyOfRange(sealedData, sOffset, sealedData.length);
        byte[] k = sender.multiply(fromBits(r)).add(R).multiply(recipient).toByteArray();

        MessageDigest digest = getDigest(symmetricKeySize);
        digest.update(SHARED_KEY);
        digest.update(k);
        digestVariableLengthBuffers(digest, senderId, recipientId, context);
        byte[] key = digest.digest();
        byte[] iv = Arrays.copyOf(sealedData, nonceSize);

        digest = getDigest(sigSize);
        digest.update(SIGN_KEY);
        digest.update(r);
        digestVariableLengthBuffers(digest, senderId, recipientId, context);
        digest.update(sealedData, nonceSize, msgLen);
        if (!sender.multiply(fromBytesModOrder(digest.digest())).isEqual(baseGeneratorProduct(fromCanonical(s)).add(R))) {
            throw new InvalidSealException("Bad signature");
        }
        Cipher cipher = initCipher(false, key, iv);
        cipher.updateAAD(context);
        try {
            return cipher.doFinal(sealedData, nonceSize, msgLen + tagSize);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException(e);
        } catch (BadPaddingException e) {
            throw new InvalidSealException(e);
        }
    }

    @Override
    public int getTagSize() {
        return tagSize;
    }

    @Override
    public int getNonceSize() {
        return nonceSize;
    }

    @Override
    public int getSigSize() {
        return sigSize;
    }

    static void checkArgs(byte[] senderId, byte[] recipientId, byte[] context) {
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

    static void digestVariableLengthBuffer(MessageDigest digest, byte[] buf) {
        digest.update((byte) (buf.length & 0xff));
        digest.update(buf);
    }

    static void digestVariableLengthBuffers(MessageDigest digest, byte[]... buffers) {
        for (byte[] buffer : buffers) {
            digestVariableLengthBuffer(digest, buffer);
        }
    }

    private static class SKey extends EncodedKeySpec implements PrivateKey {
        private SKey(byte[] encodedKey) {
            super(encodedKey);
        }

        @Override
        public String getAlgorithm() {
            return "Ristretto255";
        }

        @Override
        public String getFormat() {
            return "RAW";
        }
    }

    private static class PKey extends EncodedKeySpec implements PublicKey {
        private PKey(byte[] encodedKey) {
            super(encodedKey);
        }

        @Override
        public String getAlgorithm() {
            return "Ristretto255";
        }

        @Override
        public String getFormat() {
            return "RAW";
        }
    }
}
