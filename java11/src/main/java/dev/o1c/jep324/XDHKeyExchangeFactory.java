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
import dev.o1c.spi.InvalidProviderException;
import dev.o1c.spi.KeyCodec;
import dev.o1c.spi.KeyExchangeFactory;

import java.security.CryptoPrimitive;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class XDHKeyExchangeFactory extends KeyExchangeFactory {
    private final Algorithm algorithm;
    private final KeyCodec<PrivateKey> privateKeyCodec;
    private final KeyCodec<PublicKey> publicKeyCodec;

    XDHKeyExchangeFactory(Algorithm algorithm) {
        if (algorithm.getCryptoPrimitive() != CryptoPrimitive.KEY_AGREEMENT) {
            throw new IllegalArgumentException("Expected a key agreement algorithm but got " + algorithm);
        }
        this.algorithm = algorithm;
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance(algorithm.getAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
        privateKeyCodec = new XDHPrivateKeyCodec(algorithm, keyFactory);
        publicKeyCodec = new XDHPublicKeyCodec(algorithm, keyFactory);
    }

    @Override
    public String getAlgorithm() {
        return algorithm.getAlgorithm();
    }

    @Override
    public String getProvider() {
        return "SunEC";
    }

    @Override
    protected KeyCodec<PrivateKey> getPrivateKeyCodec() {
        return privateKeyCodec;
    }

    @Override
    protected KeyCodec<PublicKey> getPublicKeyCodec() {
        return publicKeyCodec;
    }

    public static class X25519 extends XDHKeyExchangeFactory {
        public X25519() {
            super(Algorithm.X25519);
        }
    }

    public static class X448 extends XDHKeyExchangeFactory {
        public X448() {
            super(Algorithm.X448);
        }
    }
}
