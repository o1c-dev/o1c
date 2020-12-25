/*
 * ISC License
 *
 * Copyright (c) 2020, Matt Sicker
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package dev.o1c.i2p;

import dev.o1c.spi.Algorithm;
import dev.o1c.spi.InvalidProviderException;
import dev.o1c.spi.KeyPairCodec;
import net.i2p.crypto.eddsa.EdDSAKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

public class Ed25519KeyPairCodec implements KeyPairCodec {
    private final Provider provider;
    private final KeyFactory keyFactory;
    private final KeyPairGenerator keyPairGenerator;

    public Ed25519KeyPairCodec() {
        provider = Security.getProvider(EdDSASecurityProvider.PROVIDER_NAME);
        if (provider == null) {
            throw new InvalidProviderException("EdDSA provider not installed");
        }
        try {
            keyFactory = KeyFactory.getInstance(EdDSAKey.KEY_ALGORITHM, provider);
            keyPairGenerator = KeyPairGenerator.getInstance(EdDSAKey.KEY_ALGORITHM, provider);
            keyPairGenerator.initialize(EdDSANamedCurveTable.ED_25519_CURVE_SPEC);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new InvalidProviderException(e);
        }
    }

    @Override
    public Algorithm getAlgorithm() {
        return Algorithm.Ed25519;
    }

    @Override
    public Provider getProvider() {
        return provider;
    }

    @Override
    public KeyPair generateKeyPair() {
        return keyPairGenerator.generateKeyPair();
    }

    @Override
    public byte[] encodeKey(PublicKey key) {
        EdDSAPublicKeySpec keySpec;
        try {
            keySpec = keyFactory.getKeySpec(key, EdDSAPublicKeySpec.class);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
        return keySpec.getA().toByteArray();
    }

    @Override
    public byte[] encodeKey(PrivateKey key) {
        EdDSAPrivateKeySpec keySpec;
        try {
            keySpec = keyFactory.getKeySpec(key, EdDSAPrivateKeySpec.class);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
        byte[] seed = keySpec.getSeed();
        if (seed == null) {
            throw new UnsupportedOperationException("Provided EdDSAPrivateKey argument uses pre-hashed key");
        }
        return seed;
    }

    @Override
    public PublicKey decodePublicKey(byte[] keyData) {
        EdDSAPublicKeySpec keySpec = new EdDSAPublicKeySpec(keyData, EdDSANamedCurveTable.ED_25519_CURVE_SPEC);
        try {
            return keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public PrivateKey decodePrivateKey(byte[] keyData) {
        EdDSAPrivateKeySpec keySpec = new EdDSAPrivateKeySpec(keyData, EdDSANamedCurveTable.ED_25519_CURVE_SPEC);
        try {
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
