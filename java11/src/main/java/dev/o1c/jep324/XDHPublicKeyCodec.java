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

import dev.o1c.spi.ByteOps;
import dev.o1c.spi.KeyCodec;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;

class XDHPublicKeyCodec implements KeyCodec<PublicKey> {
    private final NamedParameterSpec curve;
    private final KeyFactory keyFactory;
    private final int keySize;

    XDHPublicKeyCodec(NamedParameterSpec curve, KeyFactory keyFactory, int keySize) {
        this.curve = curve;
        this.keyFactory = keyFactory;
        this.keySize = keySize;
    }

    @Override
    public int getKeySize() {
        return keySize;
    }

    @Override
    public byte[] encode(PublicKey key) {
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
    public PublicKey decode(byte[] keyData) {
        var u = new BigInteger(1, ByteOps.reverseCopyOf(keyData));
        var keySpec = new XECPublicKeySpec(curve, u);
        try {
            return keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
