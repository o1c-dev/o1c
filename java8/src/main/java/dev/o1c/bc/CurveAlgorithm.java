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

package dev.o1c.bc;

import dev.o1c.spi.Algorithm;
import dev.o1c.spi.InvalidProviderException;
import dev.o1c.spi.KeyCodec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

class CurveAlgorithm implements Curve {
    private final Algorithm algorithm;
    private final KeyCodec<PrivateKey> privateKeyCodec;
    private final KeyCodec<PublicKey> publicKeyCodec;

    CurveAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance(algorithm.getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new InvalidProviderException(e);
        }
        privateKeyCodec = new PrivateKeyCodec(algorithm, keyFactory);
        publicKeyCodec = new PublicKeyCodec(algorithm, keyFactory);
    }

    @Override
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public KeyCodec<PrivateKey> getPrivateKeyCodec() {
        return privateKeyCodec;
    }

    @Override
    public KeyCodec<PublicKey> getPublicKeyCodec() {
        return publicKeyCodec;
    }
}
