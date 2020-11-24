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

package dev.o1c.jep324;

import dev.o1c.spi.Algorithm;
import dev.o1c.spi.KeyCodec;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;

class XDHPrivateKeyCodec implements KeyCodec<PrivateKey> {
    private final Algorithm algorithm;
    private final NamedParameterSpec curve;
    private final KeyFactory keyFactory;

    XDHPrivateKeyCodec(Algorithm algorithm, KeyFactory keyFactory) {
        this.algorithm = algorithm;
        this.curve = new NamedParameterSpec(algorithm.getAlgorithm());
        this.keyFactory = keyFactory;
    }

    @Override
    public int getKeySize() {
        return algorithm.getKeySize();
    }

    @Override
    public byte[] encode(PrivateKey key) {
        try {
            var keySpec = keyFactory.getKeySpec(key, XECPrivateKeySpec.class);
            return keySpec.getScalar();
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public PrivateKey decode(byte[] keyData) {
        try {
            return keyFactory.generatePrivate(new XECPrivateKeySpec(curve, keyData));
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
