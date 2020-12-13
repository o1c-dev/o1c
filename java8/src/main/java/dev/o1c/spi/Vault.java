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

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

public interface Vault {
    KeyPair generateKeyPair();

    SecretKey generateSecretKey();

    byte[] seal(PrivateKey senderKey, byte[] senderId, PublicKey recipientKey, byte[] recipientId, byte[] context, byte[] data);

    byte[] seal(SecretKey secretKey, byte[] context, byte[] data);

    byte[] unseal(
            PublicKey senderKey, byte[] senderId, PrivateKey recipientKey, byte[] recipientId, byte[] context,
            byte[] sealedData);

    byte[] unseal(SecretKey secretKey, byte[] context, byte[] sealedData);

    int getTagSize();

    int getNonceSize();

    int getSigSize();

    static Vault getInstance() {
        Iterator<Vault> iterator = ServiceLoader.load(Vault.class).iterator();
        InvalidProviderException error = null;
        while (iterator.hasNext()) {
            try {
                return iterator.next();
            } catch (ServiceConfigurationError e) {
                if (error == null) {
                    error = new InvalidProviderException("Could not load any vault providers");
                }
                error.addSuppressed(e.getCause() instanceof O1CException ? e.getCause() : e);
            }
        }
        throw error == null ? new InvalidProviderException("No vault providers available") : error;
    }
}
