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

import dev.o1c.spi.KeyCodec;
import dev.o1c.spi.Signature;
import net.i2p.crypto.eddsa.EdDSAEngine;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

class Ed25519Signature implements Signature {
    private final KeyCodec<PrivateKey> privateKeyCodec;
    private final KeyCodec<PublicKey> publicKeyCodec;
    private final KeyPairGenerator keyPairGenerator;

    Ed25519Signature(
            KeyCodec<PrivateKey> privateKeyCodec, KeyCodec<PublicKey> publicKeyCodec,
            KeyPairGenerator keyPairGenerator) {
        this.privateKeyCodec = privateKeyCodec;
        this.publicKeyCodec = publicKeyCodec;
        this.keyPairGenerator = keyPairGenerator;
    }

    @Override
    public KeyPair newSigningKey() {
        return keyPairGenerator.generateKeyPair();
    }

    @Override
    public byte[] calculateSignature(PrivateKey key, byte[] data) {
        EdDSAEngine engine = new EdDSAEngine();
        try {
            engine.initSign(key);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
        try {
            return engine.signOneShot(data);
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean verifySignature(PublicKey key, byte[] data, byte[] signature) {
        EdDSAEngine engine = new EdDSAEngine();
        try {
            engine.initVerify(key);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
        try {
            return engine.verifyOneShot(data, signature);
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public byte[] calculateSignature(byte[] privateKey, byte[] data) {
        return calculateSignature(privateKeyCodec.decode(privateKey), data);
    }

    @Override
    public boolean verifySignature(byte[] publicKey, byte[] data, byte[] signature) {
        return verifySignature(publicKeyCodec.decode(publicKey), data, signature);
    }
}
