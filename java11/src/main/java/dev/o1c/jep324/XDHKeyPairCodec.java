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
import dev.o1c.util.ByteOps;
import dev.o1c.spi.InvalidProviderException;
import dev.o1c.spi.KeyPairCodec;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

class XDHKeyPairCodec implements KeyPairCodec {
    private final Algorithm algorithm;
    private final NamedParameterSpec curve;
    private final KeyFactory keyFactory;
    private final KeyPairGenerator keyPairGenerator;

    XDHKeyPairCodec(Algorithm algorithm) {
        this.algorithm = algorithm;
        curve = new NamedParameterSpec(algorithm.getAlgorithm());
        try {
            keyFactory = KeyFactory.getInstance(algorithm.getAlgorithm());
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm.getAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
    }

    @Override
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public Provider getProvider() {
        return keyFactory.getProvider();
    }

    @Override
    public KeyPair generateKeyPair() {
        return keyPairGenerator.generateKeyPair();
    }

    @Override
    public byte[] encodeKey(PublicKey key) {
        try {
            var keySpec = keyFactory.getKeySpec(key, XECPublicKeySpec.class);
            var u = keySpec.getU().toByteArray();
            ByteOps.reverse(u);
            return u;
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public byte[] encodeKey(PrivateKey key) {
        try {
            var keySpec = keyFactory.getKeySpec(key, XECPrivateKeySpec.class);
            return keySpec.getScalar();
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public PublicKey decodePublicKey(byte[] keyData) {
        var u = new BigInteger(1, ByteOps.reverseCopyOf(keyData));
        var keySpec = new XECPublicKeySpec(curve, u);
        try {
            return keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public PrivateKey decodePrivateKey(byte[] keyData) {
        try {
            return keyFactory.generatePrivate(new XECPrivateKeySpec(curve, keyData));
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
