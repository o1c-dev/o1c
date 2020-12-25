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

package dev.o1c.bc;

import dev.o1c.spi.Algorithm;
import dev.o1c.spi.InvalidProviderException;
import dev.o1c.spi.KeyPairCodec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class BouncyCastleKeyPairCodec implements KeyPairCodec {
    private final Algorithm algorithm;
    private final AlgorithmIdentifier identifier;
    private final KeyFactory keyFactory;
    private final KeyPairGenerator keyPairGenerator;

    BouncyCastleKeyPairCodec(Algorithm algorithm) {
        this.algorithm = algorithm;
        identifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(algorithm.getObjectIdentifier()));
        try {
            keyFactory = KeyFactory.getInstance(algorithm.getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm.getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
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
            X509EncodedKeySpec keySpec = keyFactory.getKeySpec(key, X509EncodedKeySpec.class);
            SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keySpec.getEncoded());
            return keyInfo.getPublicKeyData().getOctets();
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public byte[] encodeKey(PrivateKey key) {
        try {
            PKCS8EncodedKeySpec keySpec = keyFactory.getKeySpec(key, PKCS8EncodedKeySpec.class);
            PrivateKeyInfo keyInfo = PrivateKeyInfo.getInstance(keySpec.getEncoded());
            return keyInfo.getPrivateKey().getOctets();
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public PublicKey decodePublicKey(byte[] keyData) {
        if (keyData.length != algorithm.getKeySize()) {
            throw new IllegalArgumentException(
                    "Invalid key size; expected " + algorithm.getKeySize() + " bytes but got " + keyData.length);
        }
        SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo(identifier, keyData);
        try {
            byte[] encoded = keyInfo.getEncoded();
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException | IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public PrivateKey decodePrivateKey(byte[] keyData) {
        if (keyData.length != algorithm.getKeySize()) {
            throw new IllegalArgumentException(
                    "Invalid key size; expected " + algorithm.getKeySize() + " bytes but got " + keyData.length);
        }
        try {
            PrivateKeyInfo keyInfo = new PrivateKeyInfo(identifier, new DEROctetString(keyData));
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyInfo.getEncoded());
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException | IOException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
