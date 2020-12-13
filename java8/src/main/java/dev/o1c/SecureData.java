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

import dev.o1c.spi.Vault;

import javax.crypto.SecretKey;
import java.util.Objects;

public final class SecureData {
    private final byte[] encryptedData;
    private final byte[] token;

    public SecureData(byte[] encryptedData, byte[] token) {
        this.encryptedData = Objects.requireNonNull(encryptedData);
        this.token = Objects.requireNonNull(token);
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    public byte[] getToken() {
        return token;
    }

    public static SecretKey generateKey() {
        return Vault.getInstance().generateSecretKey();
    }

    public static Seal usingKey(SecretKey key) {
        return new SecretKeySeal(Objects.requireNonNull(key));
    }

    public interface Seal {
        byte[] seal(byte[] data, byte[] context);

        default byte[] seal(byte[] data) {
            return seal(data, null);
        }

        byte[] unseal(byte[] sealedData, byte[] context);

        default byte[] unseal(byte[] sealedData) {
            return unseal(sealedData, null);
        }

        SecureData tokenSeal(byte[] data, byte[] context);

        default SecureData tokenSeal(byte[] data) {
            return tokenSeal(data, null);
        }

        byte[] tokenUnseal(byte[] encryptedData, byte[] token, byte[] context);

        default byte[] tokenUnseal(byte[] encryptedData, byte[] token) {
            return tokenUnseal(encryptedData, token, null);
        }
    }
}
