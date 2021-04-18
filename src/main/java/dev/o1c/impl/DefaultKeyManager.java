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

package dev.o1c.impl;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Scalar;
import dev.o1c.KeyManager;
import dev.o1c.KeyPair;
import dev.o1c.PublicKey;
import dev.o1c.SecretKey;
import dev.o1c.impl.blake3.Blake3HashFactory;
import dev.o1c.impl.blake3.Blake3RandomBytesGenerator;
import dev.o1c.spi.Hash;
import dev.o1c.spi.InvalidKeyException;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public class DefaultKeyManager implements KeyManager {
    private static final int KEY_LENGTH = 32;

    @Override
    public @NotNull KeyPair generateKeyPair() {
        return parsePrivateKey(Blake3RandomBytesGenerator.getInstance().generateBytes(KEY_LENGTH));
    }

    @Override
    public @NotNull SecretKey generateSecretKey() {
        return new DefaultSecretKey();
    }

    @Override
    public @NotNull SecretKey parseSecretKey(byte @NotNull [] secretKey) {
        return new DefaultSecretKey(secretKey);
    }

    @Override
    public @NotNull PublicKey parsePublicKey(byte @NotNull [] publicKey) {
        if (publicKey.length != KEY_LENGTH) {
            throw new InvalidKeyException("Public key must be 32 bytes");
        }
        return new DefaultPublicKey(new CompressedRistretto(publicKey));
    }

    @Override
    public @NotNull KeyPair parsePrivateKey(byte @NotNull [] privateKey) {
        if (privateKey.length != KEY_LENGTH) {
            throw new InvalidKeyException("Private key must be 32 bytes");
        }
        Hash expandHash = Blake3HashFactory.INSTANCE.newHash(64);
        expandHash.update(privateKey);
        byte[] expandedKey = expandHash.doFinalize();
        byte[] lower = Arrays.copyOf(expandedKey, KEY_LENGTH);
        byte[] upper = Arrays.copyOfRange(expandedKey, KEY_LENGTH, 64);
        lower[0] &= 248;
        lower[31] &= 127;
        lower[31] |= 64;
        Scalar scalar = Scalar.fromBits(lower);
        Hash challenge = Blake3HashFactory.INSTANCE.newKeyedHash(upper);
        return new DefaultKeyPair(scalar, challenge);
    }
}
