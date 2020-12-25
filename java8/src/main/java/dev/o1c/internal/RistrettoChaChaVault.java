/*
 * ISC License
 *
 * Copyright (c) 2020, Matt Sicker
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
 */

package dev.o1c.internal;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.InvalidEncodingException;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.RistrettoGeneratorTable;
import cafe.cryptography.curve25519.Scalar;
import dev.o1c.spi.InvalidAuthenticationTagException;
import dev.o1c.spi.InvalidProviderException;
import dev.o1c.spi.InvalidSealException;
import dev.o1c.spi.InvalidSignatureException;
import dev.o1c.spi.Vault;
import dev.o1c.util.ByteOps;
import org.bouncycastle.crypto.digests.Blake2bDigest;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

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

    private final SecureRandom secureRandom;

    public RistrettoChaChaVault() {
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
    }

    public RistrettoChaChaVault(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] key = new byte[ASYMMETRIC_KEY_SIZE];
        secureRandom.nextBytes(key);
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
        byte[] key = new byte[SYMMETRIC_KEY_SIZE];
        secureRandom.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, ALGORITHM);
        ByteOps.overwriteWithZeroes(key);
        return secretKey;
    }

    @Override
    public byte[] seal(SecretKey secretKey, byte[] context, byte[] data) {
        Objects.requireNonNull(secretKey);
        Objects.requireNonNull(context);
        Objects.requireNonNull(data);
        byte[] nonce = new byte[NONCE_SIZE];
        Cipher cipher = XChaCha20Poly1305.cryptWith(true, secretKey.getEncoded(), nonce);
        cipher.updateAAD(context);
        byte[] sealed = Arrays.copyOf(nonce, NONCE_SIZE + cipher.getOutputSize(data.length));
        ByteOps.overwriteWithZeroes(nonce);
        try {
            cipher.doFinal(data, 0, data.length, sealed, NONCE_SIZE);
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
        int msgLen = sealedData.length - NONCE_SIZE - AUTHENTICATION_TAG_SIZE;
        if (msgLen < 0) {
            throw new InvalidSealException("Missing metadata");
        }
        Cipher cipher = XChaCha20Poly1305.cryptWith(false, secretKey.getEncoded(), Arrays.copyOf(sealedData, NONCE_SIZE));
        cipher.updateAAD(context);
        try {
            return cipher.doFinal(sealedData, NONCE_SIZE, msgLen + AUTHENTICATION_TAG_SIZE);
        } catch (BadPaddingException e) {
            throw new InvalidSealException(e);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException(e);
        }
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
        Digest digest = new Digest(512);
        digest.update(NONCE);
        digest.update(senderKey.getEncoded());
        digest.update(recipientKey.getEncoded());
        byte[] noise = new byte[32];
        secureRandom.nextBytes(noise);
        digest.update(noise);
        digest.update(data);
        Scalar ephemeralPrivateKey = Scalar.fromBytesModOrderWide(digest.digest());
        RistrettoElement ephemeralPublicKey = BASE_GENERATOR.multiply(ephemeralPrivateKey);
        byte[] r = ephemeralPublicKey.compress().toByteArray(); // first half of signature
        // TODO: it seems odd that we have to flip types twice
        RistrettoElement kp = recipient.multiply(Scalar.fromBits(r).multiplyAndAdd(sender, ephemeralPrivateKey));
        byte[] k = kp.compress().toByteArray();
        digest = new Digest(256);
        digest.update(SHARED_KEY);
        digest.update(k);
        digest.updateVariableLengthBuffers(senderId, recipientId, context);
        byte[] sharedKey = digest.digest();
        digest = new Digest(512);
        digest.update(SIGN_KEY);
        digest.update(r);
        digest.updateVariableLengthBuffers(senderId, recipientId, context);
        byte[] nonce = new byte[NONCE_SIZE];
        secureRandom.nextBytes(nonce);
        Cipher cipher = XChaCha20Poly1305.cryptWith(true, sharedKey, nonce);
        cipher.updateAAD(context);
        int ctLen = NONCE_SIZE + cipher.getOutputSize(data.length);
        byte[] wrapped = Arrays.copyOf(nonce, ctLen + SIGNATURE_SIZE);
        try {
            cipher.doFinal(data, 0, data.length, wrapped, NONCE_SIZE);
        } catch (BadPaddingException | IllegalBlockSizeException | ShortBufferException e) {
            throw new IllegalStateException(e);
        }
        digest.update(wrapped, NONCE_SIZE, data.length);
        byte[] s =
                Scalar.fromBytesModOrderWide(digest.digest()).multiply(sender).subtract(ephemeralPrivateKey).toByteArray();
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
        int msgLen = wrappedData.length - NONCE_SIZE - AUTHENTICATION_TAG_SIZE - SIGNATURE_SIZE;
        if (msgLen < 0) {
            throw new InvalidSealException("Sealed data is missing metadata");
        }
        RistrettoElement sender = ((PublicKey) senderKey).key;
        Scalar recipient = ((PrivateKey) recipientKey).key;
        byte[] r =
                Arrays.copyOfRange(wrappedData, wrappedData.length - SIGNATURE_SIZE, wrappedData.length - 32);
        byte[] s = Arrays.copyOfRange(wrappedData, wrappedData.length - 32, wrappedData.length);
        Scalar reduced = Scalar.fromBits(r);
        RistrettoElement publicSigningKey;
        try {
            publicSigningKey = new CompressedRistretto(r).decompress();
        } catch (InvalidEncodingException e) {
            throw new InvalidSealException(e);
        }
        byte[] k = sender.multiply(reduced).add(publicSigningKey).multiply(recipient).compress().toByteArray();
        Digest digest = new Digest(256);
        digest.update(SHARED_KEY);
        digest.update(k);
        digest.updateVariableLengthBuffers(senderId, recipientId, context);
        byte[] sharedKey = digest.digest();
        byte[] nonce = Arrays.copyOf(wrappedData, NONCE_SIZE);
        digest = new Digest(512);
        digest.update(SIGN_KEY);
        digest.update(r);
        digest.updateVariableLengthBuffers(senderId, recipientId, context);
        digest.update(wrappedData, NONCE_SIZE, msgLen);
        if (sender.multiply(Scalar.fromBytesModOrderWide(digest.digest()))
                .ctEquals(BASE_GENERATOR.multiply(Scalar.fromCanonicalBytes(s)).add(publicSigningKey)) != 1) {
            throw new InvalidSignatureException("Bad signature");
        }
        Cipher cipher = XChaCha20Poly1305.cryptWith(false, sharedKey, nonce);
        cipher.updateAAD(context);
        try {
            return cipher.doFinal(wrappedData, NONCE_SIZE, msgLen + AUTHENTICATION_TAG_SIZE);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalStateException(e);
        } catch (AEADBadTagException e) {
            throw new InvalidAuthenticationTagException(e.getMessage());
        } catch (BadPaddingException e) {
            throw new InvalidSealException(e);
        }
    }

    @Override
    public int getTagSize() {
        return AUTHENTICATION_TAG_SIZE;
    }

    @Override
    public int getNonceSize() {
        return NONCE_SIZE;
    }

    @Override
    public int getSigSize() {
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

    private static class Digest {
        private final Blake2bDigest delegate;

        Digest(int hashSize) {
            delegate = new Blake2bDigest(hashSize);
        }

        public void update(byte[] message) {
            delegate.update(message, 0, message.length);
        }

        public void update(byte[] message, int offset, int len) {
            delegate.update(message, offset, len);
        }

        public void updateVariableLengthBuffers(byte[]... buffers) {
            for (byte[] buffer : buffers) {
                delegate.update((byte) (buffer.length & 0xff));
                delegate.update(buffer, 0, buffer.length);
            }
        }

        public byte[] digest() {
            byte[] digest = new byte[delegate.getDigestSize()];
            delegate.doFinal(digest, 0);
            return digest;
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
