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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.function.Supplier;

class DefaultCipher implements Cipher {
    private final SecureRandom secureRandom;
    private final KeyGenerator keyGenerator;
    private final KeyCodec<SecretKey> secretKeyCodec;
    private final Supplier<javax.crypto.Cipher> cipherSupplier;

    DefaultCipher(
            SecureRandom secureRandom, KeyGenerator keyGenerator, KeyCodec<SecretKey> secretKeyCodec,
            Supplier<javax.crypto.Cipher> cipherSupplier) {
        this.secureRandom = secureRandom;
        this.keyGenerator = keyGenerator;
        this.keyGenerator.init(secureRandom);
        this.secretKeyCodec = secretKeyCodec;
        this.cipherSupplier = cipherSupplier;
    }

    @Override
    public SecretKey newKey() {
        return keyGenerator.generateKey();
    }

    @Override
    public byte[] newNonce() {
        byte[] nonce = new byte[12];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    @Override
    public byte[] encrypt(byte[] key, byte[] nonce, byte[] plaintext) {
        return encrypt(secretKeyCodec.decode(key), nonce, plaintext);
    }

    @Override
    public byte[] encrypt(SecretKey key, byte[] nonce, byte[] plaintext) {
        return crypt(init(true, key, nonce), plaintext);
    }

    @Override
    public byte[] encryptAAD(byte[] key, byte[] nonce, byte[] plaintext, byte[] additionalAuthenticatedData) {
        return encryptAAD(secretKeyCodec.decode(key), nonce, plaintext, additionalAuthenticatedData);
    }

    @Override
    public byte[] encryptAAD(SecretKey key, byte[] nonce, byte[] plaintext, byte[] additionalAuthenticatedData) {
        javax.crypto.Cipher cipher = init(true, key, nonce);
        cipher.updateAAD(additionalAuthenticatedData);
        return crypt(cipher, plaintext);
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] nonce, byte[] ciphertext) {
        return decrypt(secretKeyCodec.decode(key), nonce, ciphertext);
    }

    @Override
    public byte[] decrypt(SecretKey key, byte[] nonce, byte[] ciphertext) {
        return crypt(init(false, key, nonce), ciphertext);
    }

    @Override
    public byte[] decryptAAD(byte[] key, byte[] nonce, byte[] ciphertext, byte[] additionalAuthenticatedData) {
        return decryptAAD(secretKeyCodec.decode(key), nonce, ciphertext, additionalAuthenticatedData);
    }

    @Override
    public byte[] decryptAAD(SecretKey key, byte[] nonce, byte[] ciphertext, byte[] additionalAuthenticatedData) {
        javax.crypto.Cipher cipher = init(false, key, nonce);
        cipher.updateAAD(additionalAuthenticatedData);
        return crypt(cipher, ciphertext);
    }

    private javax.crypto.Cipher init(boolean encrypt, SecretKey key, byte[] nonce) {
        javax.crypto.Cipher cipher = cipherSupplier.get();
        int mode = encrypt ? javax.crypto.Cipher.ENCRYPT_MODE : javax.crypto.Cipher.DECRYPT_MODE;
        try {
            cipher.init(mode, key, new IvParameterSpec(nonce));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
        return cipher;
    }

    private static byte[] crypt(javax.crypto.Cipher cipher, byte[] data) {
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            // as a stream cipher, neither of these exceptions are expected
            throw new IllegalStateException(e);
        }
    }
}
