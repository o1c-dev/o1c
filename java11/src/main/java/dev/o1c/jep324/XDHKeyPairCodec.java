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
