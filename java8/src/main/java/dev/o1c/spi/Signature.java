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

import java.security.PrivateKey;
import java.security.PublicKey;

public interface Signature {
    KeyPairCodec getKeyPairCodec();

    byte[] calculateSignature(PrivateKey key, byte[] data);

    boolean verifySignature(PublicKey key, byte[] data, byte[] signature);

    default byte[] calculateSignature(byte[] privateKey, byte[] data) {
        return calculateSignature(getKeyPairCodec().decodePrivateKey(privateKey), data);
    }

    default boolean verifySignature(byte[] publicKey, byte[] data, byte[] signature) {
        return verifySignature(getKeyPairCodec().decodePublicKey(publicKey), data, signature);
    }

    static Signature getInstance(Algorithm algorithm) {
        return SecurityFactory.getInstance(SignatureFactory.class, factory -> algorithm == factory.getAlgorithm(),
                () -> "No SignatureFactory providers found for " + algorithm).create();
    }
}
