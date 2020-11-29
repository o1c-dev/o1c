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

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

class DefaultKeyExchange implements KeyExchange {
    private final KeyPairCodec keyPairCodec;

    DefaultKeyExchange(KeyPairCodec keyPairCodec) {
        this.keyPairCodec = keyPairCodec;
    }

    @Override
    public KeyPair newExchangeKey() {
        return keyPairCodec.generateKeyPair();
    }

    @Override
    public SecretKey calculateSharedSecret(PrivateKey us, PublicKey them) {
        try {
            KeyAgreement agreement = createKeyAgreement();
            agreement.init(us);
            agreement.doPhase(them, true);
            return agreement.generateSecret("ChaCha20");
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public byte[] calculateSharedSecret(byte[] ourPrivateKey, byte[] theirPublicKey) {
        try {
            KeyAgreement agreement = createKeyAgreement();
            agreement.init(keyPairCodec.decodePrivateKey(ourPrivateKey));
            agreement.doPhase(keyPairCodec.decodePublicKey(theirPublicKey), true);
            return agreement.generateSecret();
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private KeyAgreement createKeyAgreement() throws NoSuchAlgorithmException {
        return KeyAgreement.getInstance(keyPairCodec.getAlgorithm().getAlgorithm(), keyPairCodec.getProvider());
    }
}
