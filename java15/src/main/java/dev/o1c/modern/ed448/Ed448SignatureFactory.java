/*
 * ISC License
 *
 * Copyright (c) 2021, Matt Sicker
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
 *
 * SPDX-License-Identifier: ISC
 */

package dev.o1c.modern.ed448;

import dev.o1c.spi.PrivateKey;
import dev.o1c.spi.PublicKey;
import dev.o1c.spi.SignatureFactory;
import dev.o1c.spi.SigningKey;
import dev.o1c.spi.VerifyingKey;
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;

public class Ed448SignatureFactory implements SignatureFactory {
    private final KeyPairGenerator keyPairGenerator = Ed448.getKeyPairGenerator();
    private final KeyFactory keyFactory = Ed448.getKeyFactory();

    @Override
    public int keyLength() {
        return 57;
    }

    @Override
    public @NotNull SigningKey generateKey() {
        return new Ed448SigningKey(keyPairGenerator.generateKeyPair());
    }

    @Override
    public @NotNull SigningKey parseKey(@NotNull PrivateKey privateKey) {
        return parsePrivateKey(privateKey.key());
    }

    @Override
    public @NotNull VerifyingKey parseKey(@NotNull PublicKey publicKey) {
        return parsePublicKey(publicKey.key());
    }

    @Override
    public @NotNull SigningKey parsePrivateKey(byte @NotNull [] key) {
        // TODO: generate public key from private key
        throw new UnsupportedOperationException("No public key");
    }

    @Override
    public @NotNull VerifyingKey parsePublicKey(byte @NotNull [] key) {
        // little endian, high order bit specifies if x is odd or not
        // this bit of glue code inspired from:
        // https://bugs.openjdk.java.net/browse/JDK-8252595
        var bigEndianForm = ByteOps.reverseCopyOf(key);
        var xOdd = (bigEndianForm[0] & 0x80) != 0;
        bigEndianForm[0] &= 0x7f;
        var y = new BigInteger(bigEndianForm);
        var point = new EdECPoint(xOdd, y);
        try {
            return new Ed448VerifyingKey(keyFactory.generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED448, point)));
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
