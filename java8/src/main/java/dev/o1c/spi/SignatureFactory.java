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

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class SignatureFactory implements SecurityFactory<Signature> {
    @Override
    public final Signature create() {
        return new Signature(getPrivateKeyCodec(), getPublicKeyCodec(), getKeyPairGenerator(), this::createSignature);
    }

    protected abstract KeyCodec<PrivateKey> getPrivateKeyCodec();

    protected abstract KeyCodec<PublicKey> getPublicKeyCodec();

    protected KeyPairGenerator getKeyPairGenerator() {
        try {
            return KeyPairGenerator.getInstance(getAlgorithm(), getProvider());
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new InvalidProviderException(e);
        }
    }

    protected java.security.Signature createSignature() {
        try {
            return java.security.Signature.getInstance(getAlgorithm(), getProvider());
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new InvalidProviderException(e);
        }
    }
}
