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

import dev.o1c.O1CException;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;

public class CipherFactory implements SecurityFactory<Cipher>, KeyCodec<SecretKey> {
    private final String provider;

    public CipherFactory(String provider) {
        if (Security.getProvider(provider) == null) {
            throw new ProviderException("Provider '" + provider + "' not installed");
        }
        this.provider = provider;
    }

    @Override
    public final Cipher create() {
        return new Cipher(getSecureRandom(), getKeyGenerator(), this, this::createCipher);
    }

    @Override
    public int getKeySize() {
        return Algorithm.ChaCha20Poly1305.getKeySize();
    }

    @Override
    public String getAlgorithm() {
        return Algorithm.ChaCha20Poly1305.getAlgorithm();
    }

    @Override
    public String getProvider() {
        return provider;
    }

    protected SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new O1CException("Strong secure random generator required", e);
        }
    }

    protected KeyGenerator getKeyGenerator() {
        try {
            return KeyGenerator.getInstance("ChaCha20", getProvider());
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new InvalidProviderException(e);
        }
    }

    protected javax.crypto.Cipher createCipher() {
        try {
            return javax.crypto.Cipher.getInstance(getAlgorithm(), getProvider());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            throw new InvalidProviderException(e);
        }
    }

    @Override
    public byte[] encode(SecretKey key) {
        return key.getEncoded();
    }

    @Override
    public SecretKey decode(byte[] keyData) {
        if (keyData.length != getKeySize()) {
            throw new IllegalArgumentException(
                    "Invalid key size. Expected " + getKeySize() + " bytes but got " + keyData.length);
        }
        return new SecretKeySpec(keyData, "ChaCha20");
    }
}
