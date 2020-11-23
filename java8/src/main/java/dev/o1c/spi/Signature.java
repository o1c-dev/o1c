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

package dev.o1c.spi;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.function.Supplier;

public final class Signature {
    private final KeyCodec<PrivateKey> privateKeyCodec;
    private final KeyCodec<PublicKey> publicKeyCodec;
    private final KeyPairGenerator keyPairGenerator;
    private final Supplier<java.security.Signature> signatureSupplier;

    // TODO: API bridge to SignedObject

    Signature(
            KeyCodec<PrivateKey> privateKeyCodec, KeyCodec<PublicKey> publicKeyCodec,
            KeyPairGenerator keyPairGenerator, Supplier<java.security.Signature> signatureSupplier) {
        this.privateKeyCodec = privateKeyCodec;
        this.publicKeyCodec = publicKeyCodec;
        this.keyPairGenerator = keyPairGenerator;
        this.signatureSupplier = signatureSupplier;
    }

    public KeyPair newSigningKey() {
        return keyPairGenerator.generateKeyPair();
    }

    public byte[] calculateSignature(PrivateKey key, byte[] data) {
        java.security.Signature signature = signatureSupplier.get();
        try {
            signature.initSign(key);
            signature.update(data);
            return signature.sign();
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    public boolean verifySignature(PublicKey key, byte[] data, byte[] signature) {
        java.security.Signature verification = signatureSupplier.get();
        try {
            verification.initVerify(key);
            verification.update(data);
            return verification.verify(signature);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    public byte[] calculateSignature(byte[] privateKey, byte[] data) {
        return calculateSignature(privateKeyCodec.decode(privateKey), data);
    }

    public boolean verifySignature(byte[] publicKey, byte[] data, byte[] signature) {
        return verifySignature(publicKeyCodec.decode(publicKey), data, signature);
    }
}
