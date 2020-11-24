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
import dev.o1c.spi.KeyCodec;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

class EdDSAPublicKeyCodec implements KeyCodec<PublicKey> {
    private final Algorithm algorithm;
    private final NamedParameterSpec curve;
    private final KeyFactory keyFactory;

    EdDSAPublicKeyCodec(Algorithm algorithm, KeyFactory keyFactory) {
        this.algorithm = algorithm;
        this.curve = new NamedParameterSpec(algorithm.getAlgorithm());
        this.keyFactory = keyFactory;
    }

    @Override
    public int getKeySize() {
        return algorithm.getKeySize();
    }

    @Override
    public byte[] encode(PublicKey key) {
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
        var keyData = Arrays.copyOf(y, getKeySize());
        keyData[keyData.length - 1] |= (byte) (point.isXOdd() ? 0x80 : 0);
        return keyData;
    }

    @Override
    public PublicKey decode(byte[] keyData) {
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
}
