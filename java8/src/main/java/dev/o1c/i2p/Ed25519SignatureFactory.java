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
import dev.o1c.spi.InvalidProviderException;
import dev.o1c.spi.KeyCodec;
import dev.o1c.spi.Signature;
import dev.o1c.spi.SignatureFactory;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Ed25519SignatureFactory extends SignatureFactory {
    private final KeyPairGenerator keyPairGenerator;
    private final KeyCodec<PrivateKey> privateKeyCodec;
    private final KeyCodec<PublicKey> publicKeyCodec;

    public Ed25519SignatureFactory() {
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance(EdDSAKey.KEY_ALGORITHM, EdDSASecurityProvider.PROVIDER_NAME);
            keyPairGenerator = KeyPairGenerator.getInstance(EdDSAKey.KEY_ALGORITHM, EdDSASecurityProvider.PROVIDER_NAME);
            keyPairGenerator.initialize(EdDSANamedCurveTable.ED_25519_CURVE_SPEC);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new InvalidProviderException(e);
        }
        privateKeyCodec = new Ed25519PrivateKeyCodec(keyFactory);
        publicKeyCodec = new Ed25519PublicKeyCodec(keyFactory);
    }

    @Override
    public String getAlgorithm() {
        return Algorithm.Ed25519.getAlgorithm();
    }

    @Override
    public String getProvider() {
        return EdDSASecurityProvider.PROVIDER_NAME;
    }

    @Override
    public Signature create() {
        return new Ed25519Signature(getPrivateKeyCodec(), getPublicKeyCodec(), getKeyPairGenerator());
    }

    @Override
    protected KeyCodec<PrivateKey> getPrivateKeyCodec() {
        return privateKeyCodec;
    }

    @Override
    protected KeyCodec<PublicKey> getPublicKeyCodec() {
        return publicKeyCodec;
    }

    @Override
    protected java.security.Signature createSignature() {
        return new EdDSAEngine();
    }

    @Override
    protected KeyPairGenerator getKeyPairGenerator() {
        return keyPairGenerator;
    }
}
