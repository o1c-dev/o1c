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

package dev.o1c.i2p;

import dev.o1c.spi.Algorithm;
import dev.o1c.spi.KeyCodec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

class Ed25519PrivateKeyCodec implements KeyCodec<PrivateKey> {
    private final KeyFactory keyFactory;

    Ed25519PrivateKeyCodec(KeyFactory keyFactory) {
        this.keyFactory = keyFactory;
    }

    @Override
    public int getKeySize() {
        return Algorithm.Ed25519.getKeySize();
    }

    @Override
    public byte[] encode(PrivateKey key) {
        EdDSAPrivateKeySpec keySpec;
        try {
            keySpec = keyFactory.getKeySpec(key, EdDSAPrivateKeySpec.class);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
        byte[] seed = keySpec.getSeed();
        if (seed == null) {
            throw new UnsupportedOperationException("Provided EdDSAPrivateKey argument uses pre-hashed key");
        }
        return seed;
    }

    @Override
    public PrivateKey decode(byte[] keyData) {
        EdDSAPrivateKeySpec keySpec = new EdDSAPrivateKeySpec(keyData, EdDSANamedCurveTable.ED_25519_CURVE_SPEC);
        try {
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
