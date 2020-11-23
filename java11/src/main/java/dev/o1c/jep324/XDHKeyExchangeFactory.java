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

import dev.o1c.spi.InvalidProviderException;
import dev.o1c.spi.KeyCodec;
import dev.o1c.spi.KeyExchangeFactory;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;

public class XDHKeyExchangeFactory extends KeyExchangeFactory {
    private final NamedParameterSpec curve;
    private final KeyCodec<PrivateKey> privateKeyCodec;
    private final KeyCodec<PublicKey> publicKeyCodec;

    XDHKeyExchangeFactory(NamedParameterSpec curve) {
        this.curve = curve;
        int keySize;
        switch (curve.getName()) {
            case "X25519":
                keySize = 32;
                break;
            case "X448":
                keySize = 56;
                break;

            default:
                throw new IllegalArgumentException("Expected an XDH curve but got " + curve.getName());
        }
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance(curve.getName());
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
        privateKeyCodec = new XDHPrivateKeyCodec(curve, keyFactory, keySize);
        publicKeyCodec = new XDHPublicKeyCodec(curve, keyFactory, keySize);
    }

    @Override
    public String getAlgorithm() {
        return curve.getName();
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
            super(NamedParameterSpec.X25519);
        }
    }

    public static class X448 extends XDHKeyExchangeFactory {
        public X448() {
            super(NamedParameterSpec.X448);
        }
    }
}
