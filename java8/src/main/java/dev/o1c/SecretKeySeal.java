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

package dev.o1c;

import dev.o1c.spi.Algorithm;
import dev.o1c.spi.ByteOps;
import dev.o1c.spi.InvalidProviderException;
import dev.o1c.spi.InvalidSealException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

class SecretKeySeal implements SecureData.Seal {
    private static final int TAG_SIZE = 16;
    private static final int NONCE_SIZE = 12;
    private static final int SEAL_TYPE = 0x43433230; // CC20 in ASCII, big endian order
    private static final int TOKEN_SIZE = NONCE_SIZE + TAG_SIZE + Integer.BYTES;
    // token = tag [0..15] + nonce [16..27] + seal_type [28..31]

    private final SecretKey key;

    SecretKeySeal(SecretKey key) {
        this.key = key;
    }

    @Override
    public byte[] seal(byte[] data, byte[] context) {
        Objects.requireNonNull(data);
        Cipher cipher = initEncrypt(context);
        byte[] nonce = cipher.getIV();
        ByteBuffer sealedData = ByteBuffer.allocate(cipher.getOutputSize(data.length) + nonce.length + Integer.BYTES * 2);
        sealedData.putInt(SEAL_TYPE);
        sealedData.putInt(data.length);
        sealedData.put(nonce);
        try {
            cipher.doFinal(ByteBuffer.wrap(data), sealedData);
        } catch (BadPaddingException | IllegalBlockSizeException | ShortBufferException e) {
            throw new IllegalStateException(e);
        }
        return sealedData.array();
    }

    @Override
    public byte[] unseal(byte[] sealedData, byte[] context) {
        Objects.requireNonNull(sealedData);
        int sealType = ByteOps.unpackIntBE(sealedData, 0);
        if (sealType != SEAL_TYPE) {
            throw new InvalidSealException("Unsupported seal type detected: " + Integer.toHexString(sealType));
        }
        int dataLength = ByteOps.unpackIntBE(sealedData, Integer.BYTES) + TAG_SIZE;
        int nonceOffset = Integer.BYTES * 2;
        IvParameterSpec nonce = new IvParameterSpec(sealedData, nonceOffset, NONCE_SIZE);
        int dataOffset = nonceOffset + NONCE_SIZE;
        try {
            return initDecrypt(nonce, context).doFinal(sealedData, dataOffset, dataLength);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new InvalidSealException(e);
        }
    }

    @Override
    public SecureData tokenSeal(byte[] data, byte[] context) {
        Objects.requireNonNull(data);
        Cipher cipher = initEncrypt(context);
        byte[] nonce = cipher.getIV();
        ByteBuffer ciphertext = ByteBuffer.allocate(cipher.getOutputSize(data.length));
        try {
            cipher.doFinal(ByteBuffer.wrap(data), ciphertext);
        } catch (BadPaddingException | IllegalBlockSizeException | ShortBufferException e) {
            throw new IllegalStateException(e);
        }
        ciphertext.flip();
        byte[] encryptedData = new byte[data.length];
        ciphertext.get(encryptedData);
        ByteBuffer token = ByteBuffer.allocate(TOKEN_SIZE);
        token.put(ciphertext);
        token.put(nonce);
        token.putInt(SEAL_TYPE);
        return new SecureData(encryptedData, token.array());
    }

    @Override
    public byte[] tokenUnseal(byte[] encryptedData, byte[] token, byte[] context) {
        Objects.requireNonNull(encryptedData);
        Objects.requireNonNull(token);
        if (token.length != TOKEN_SIZE) {
            throw new InvalidSealException("Token size must be " + TOKEN_SIZE + " bytes");
        }
        int tokenType = ByteOps.unpackIntBE(token, TAG_SIZE + NONCE_SIZE);
        if (tokenType != SEAL_TYPE) {
            throw new InvalidSealException("Unsupported seal token type detected: " + Integer.toHexString(tokenType));
        }
        IvParameterSpec nonce = new IvParameterSpec(token, TAG_SIZE, NONCE_SIZE);
        Cipher cipher = initDecrypt(nonce, context);
        byte[] plaintext = new byte[encryptedData.length];
        try {
            cipher.doFinal(token, 0, TAG_SIZE, plaintext,
                    cipher.update(encryptedData, 0, encryptedData.length, plaintext));
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new InvalidSealException(e);
        } catch (ShortBufferException e) {
            throw new IllegalStateException(e);
        }
        return plaintext;
    }

    private Cipher initEncrypt(byte[] context) {
        Cipher cipher = createCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, SecureRandom.getInstanceStrong());
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
        if (context != null && context.length > 0) {
            cipher.updateAAD(context);
        }
        return cipher;
    }

    private Cipher initDecrypt(IvParameterSpec nonce, byte[] context) {
        Cipher cipher = createCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, nonce);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
        if (context != null && context.length > 0) {
            cipher.updateAAD(context);
        }
        return cipher;
    }

    private static Cipher createCipher() {
        try {
            return Cipher.getInstance(Algorithm.ChaCha20Poly1305.getAlgorithm());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new InvalidProviderException(e);
        }
    }
}
