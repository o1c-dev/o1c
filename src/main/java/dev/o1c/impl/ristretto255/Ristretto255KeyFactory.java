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

package dev.o1c.impl.ristretto255;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Scalar;
import dev.o1c.impl.blake3.Blake3HashFactory;
import dev.o1c.impl.blake3.Blake3RandomBytesGenerator;
import dev.o1c.spi.Hash;
import dev.o1c.spi.InvalidKeyException;
import dev.o1c.spi.KeyFactory;
import dev.o1c.spi.PublicKey;
import dev.o1c.spi.KeyPair;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public class Ristretto255KeyFactory implements KeyFactory {
    private final Hash expandHash = Blake3HashFactory.INSTANCE.newKeyDerivationFunction("expand_key");

    @Override
    public @NotNull KeyPair generateKey(byte @NotNull [] id) {
        byte[] keyData = Blake3RandomBytesGenerator.getInstance().generateBytes(32);
        return parsePrivateKey(id, keyData);
    }

    @Override
    public @NotNull KeyPair parsePrivateKey(byte @NotNull [] id, byte @NotNull [] keyData) {
        if (keyData.length != 32) {
            throw new InvalidKeyException("Keys must be 32 bytes");
        }
        byte[] expandedKey = new byte[64];
        expandHash.reset();
        expandHash.update(keyData);
        expandHash.doFinalize(expandedKey);
        byte[] lower = Arrays.copyOf(expandedKey, 32);
        byte[] upper = Arrays.copyOfRange(expandedKey, 32, 64);
        lower[0] &= 248;
        lower[31] &= 127;
        lower[31] |= 64;
        Scalar scalar = Scalar.fromBits(lower);
        Hash challenge = Blake3HashFactory.INSTANCE.newKeyedHash(upper);
        return new Ristretto255KeyPair(id, scalar, challenge);
    }

    @Override
    public @NotNull PublicKey parsePublicKey(byte @NotNull [] id, byte @NotNull [] keyData) {
        if (keyData.length != 32) {
            throw new InvalidKeyException("Keys must be 32 bytes");
        }
        return new Ristretto255PublicKey(id, new CompressedRistretto(keyData.clone()));
    }
}
