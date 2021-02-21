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

package dev.o1c.modern.ristretto255;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Scalar;
import dev.o1c.modern.blake3.Blake3HashFactory;
import dev.o1c.modern.blake3.Blake3RandomBytesGenerator;
import dev.o1c.spi.Certificate;
import dev.o1c.spi.CertificateFactory;
import dev.o1c.spi.CryptoHash;
import dev.o1c.spi.HashFactory;
import dev.o1c.spi.InvalidKeyException;
import dev.o1c.spi.PrivateKey;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public class Ristretto255B3CertificateFactory implements CertificateFactory {
    private final HashFactory blake3 = new Blake3HashFactory();

    @Override
    public @NotNull Certificate parsePublicKey(byte @NotNull [] publicKey) {
        return new Ristretto255B3Certificate(new CompressedRistretto(publicKey));
    }

    @Override
    public @NotNull PrivateKey parsePrivateKey(byte @NotNull [] privateKey) {
        if (privateKey.length != 32) {
            throw new InvalidKeyException("Keys must be 32 bytes");
        }
        byte[] hash = new byte[64];
        blake3.init(privateKey).finish(hash);
        byte[] lower = Arrays.copyOf(hash, 32);
        byte[] upper = Arrays.copyOfRange(hash, 32, 64);
        lower[0] &= 248;
        lower[31] &= 127;
        lower[31] |= 64;
        Scalar scalar = Scalar.fromBits(lower);
        CryptoHash challenge = blake3.init(upper);
        return new Ristretto255B3PrivateKey(scalar, challenge);
    }

    @Override
    public @NotNull PrivateKey generateKey() {
        return parsePrivateKey(Blake3RandomBytesGenerator.getInstance().generateBytes(32));
    }
}
