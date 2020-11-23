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
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.function.Supplier;

public final class KeyExchange {
    private final KeyCodec<PrivateKey> privateKeyCodec;
    private final KeyCodec<PublicKey> publicKeyCodec;
    private final KeyPairGenerator keyPairGenerator;
    private final Supplier<KeyAgreement> keyAgreementSupplier;

    KeyExchange(
            KeyCodec<PrivateKey> privateKeyCodec, KeyCodec<PublicKey> publicKeyCodec,
            KeyPairGenerator keyPairGenerator, Supplier<KeyAgreement> keyAgreementSupplier) {
        this.privateKeyCodec = privateKeyCodec;
        this.publicKeyCodec = publicKeyCodec;
        this.keyPairGenerator = keyPairGenerator;
        this.keyAgreementSupplier = keyAgreementSupplier;
    }

    public KeyPair newExchangeKey() {
        return keyPairGenerator.generateKeyPair();
    }

    public byte[] calculateSharedSecret(PrivateKey us, PublicKey them) {
        KeyAgreement agreement = keyAgreementSupplier.get();
        try {
            agreement.init(us);
            agreement.doPhase(them, true);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
        return agreement.generateSecret();
    }

    public byte[] calculateSharedSecret(byte[] ourPrivateKey, byte[] theirPublicKey) {
        return calculateSharedSecret(privateKeyCodec.decode(ourPrivateKey), publicKeyCodec.decode(theirPublicKey));
    }
}
