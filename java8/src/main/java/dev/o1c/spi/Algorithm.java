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

import java.security.CryptoPrimitive;

public enum Algorithm {
    ChaCha20Poly1305("ChaCha20-Poly1305", CryptoPrimitive.STREAM_CIPHER, 32, "1.2.840.113549.1.9.16.3.18"),
    X25519("X25519", CryptoPrimitive.KEY_AGREEMENT, 32, "1.3.101.110"),
    X448("X448", CryptoPrimitive.KEY_AGREEMENT, 56, "1.3.101.111"),
    Ed25519("Ed25519", CryptoPrimitive.SIGNATURE, 32, "1.3.101.112"),
    Ed448("Ed448", CryptoPrimitive.SIGNATURE, 57, "1.3.101.113"),
    Argon2i("Argon2i", CryptoPrimitive.KEY_ENCAPSULATION, 32, "TODO");

    private final String algorithm;
    private final CryptoPrimitive cryptoPrimitive;
    private final int keySize;
    // https://www.rfc-editor.org/info/rfc8410
    private final String objectIdentifier;

    Algorithm(String algorithm, CryptoPrimitive cryptoPrimitive, int keySize, String objectIdentifier) {
        this.algorithm = algorithm;
        this.cryptoPrimitive = cryptoPrimitive;
        this.keySize = keySize;
        this.objectIdentifier = objectIdentifier;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public CryptoPrimitive getCryptoPrimitive() {
        return cryptoPrimitive;
    }

    public int getKeySize() {
        return keySize;
    }

    public String getObjectIdentifier() {
        return objectIdentifier;
    }
}
