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

package dev.o1c.jep339;

import dev.o1c.spi.Algorithm;
import dev.o1c.spi.ByteOps;
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
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

class EdDSAKeyPairCodec implements KeyPairCodec {
    private final Algorithm algorithm;
    private final NamedParameterSpec curve;
    private final KeyFactory keyFactory;
    private final KeyPairGenerator keyPairGenerator;

    EdDSAKeyPairCodec(Algorithm algorithm) {
        this.algorithm = algorithm;
        curve = new NamedParameterSpec(algorithm.getAlgorithm());
        try {
            keyFactory = KeyFactory.getInstance(algorithm.getAlgorithm());
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm.getAlgorithm(), keyFactory.getProvider());
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
        EdECPoint point;
        try {
            var keySpec = keyFactory.getKeySpec(key, EdECPublicKeySpec.class);
            point = keySpec.getPoint();
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
        // little endian, high order bit specifies if x is odd or not
        // this bit of glue code inspired from:
        // https://bugs.openjdk.java.net/browse/JDK-8252595
        var y = point.getY().toByteArray();
        ByteOps.reverse(y);
        // zero-extend or truncate key back to key size
        var keyData = Arrays.copyOf(y, algorithm.getKeySize());
        keyData[keyData.length - 1] |= (byte) (point.isXOdd() ? 0x80 : 0);
        return keyData;
    }

    @Override
    public byte[] encodeKey(PrivateKey key) {
        try {
            var keySpec = keyFactory.getKeySpec(key, EdECPrivateKeySpec.class);
            return keySpec.getBytes();
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public PublicKey decodePublicKey(byte[] keyData) {
        // little endian, high order bit specifies if x is odd or not
        // this bit of glue code inspired from:
        // https://bugs.openjdk.java.net/browse/JDK-8252595
        var key = ByteOps.reverseCopyOf(keyData);
        var xOdd = (key[0] & 0x80) != 0;
        key[0] &= (byte) 0x7f;
        var y = new BigInteger(key);
        var point = new EdECPoint(xOdd, y);
        try {
            return keyFactory.generatePublic(new EdECPublicKeySpec(curve, point));
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public PrivateKey decodePrivateKey(byte[] keyData) {
        try {
            return keyFactory.generatePrivate(new EdECPrivateKeySpec(curve, keyData));
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
