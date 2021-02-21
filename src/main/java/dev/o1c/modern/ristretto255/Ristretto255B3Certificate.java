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
import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.InvalidEncodingException;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.Scalar;
import dev.o1c.modern.blake3.Blake3HashFactory;
import dev.o1c.spi.Certificate;
import dev.o1c.spi.CryptoHash;
import dev.o1c.spi.HashFactory;
import dev.o1c.spi.InvalidKeyException;
import dev.o1c.spi.InvalidSignatureException;
import org.jetbrains.annotations.NotNull;

import java.nio.BufferUnderflowException;
import java.util.Arrays;

public class Ristretto255B3Certificate implements Certificate {
    static final HashFactory BLAKE3 = new Blake3HashFactory();

    private final byte[] id;
    private final RistrettoElement element;
    private final RistrettoElement negatedElement;
    private final CompressedRistretto publicKey;

    Ristretto255B3Certificate(byte @NotNull [] id, @NotNull RistrettoElement element) {
        this.id = id.clone();
        this.element = element;
        negatedElement = element.negate();
        publicKey = element.compress();
    }

    Ristretto255B3Certificate(byte @NotNull [] id, @NotNull CompressedRistretto publicKey) {
        this.id = id.clone();
        this.publicKey = publicKey;
        try {
            element = publicKey.decompress();
        } catch (InvalidEncodingException e) {
            throw new InvalidKeyException(e);
        }
        negatedElement = element.negate();
    }

    Ristretto255B3Certificate(@NotNull RistrettoElement element) {
        this.element = element;
        negatedElement = element.negate();
        publicKey = element.compress();
        id = publicKey.toByteArray();
    }

    Ristretto255B3Certificate(@NotNull CompressedRistretto publicKey) {
        this.publicKey = publicKey;
        id = publicKey.toByteArray();
        try {
            element = publicKey.decompress();
        } catch (InvalidEncodingException e) {
            throw new InvalidKeyException(e);
        }
        negatedElement = element.negate();
    }

    @Override
    public byte @NotNull [] id() {
        return id.clone();
    }

    @Override
    public byte @NotNull [] publicKey() {
        return publicKey.toByteArray().clone();
    }

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public int signatureLength() {
        return 64;
    }

    @Override
    public void verify(byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset) {
        if (offset + length > message.length) {
            throw new BufferUnderflowException();
        }
        if (sigOffset + signatureLength() > signature.length) {
            throw new BufferUnderflowException();
        }

        byte[] r = Arrays.copyOfRange(signature, sigOffset, sigOffset + 32);
        RistrettoElement R;
        try {
            R = new CompressedRistretto(r).decompress();
        } catch (InvalidEncodingException e) {
            throw new InvalidSignatureException(e);
        }
        byte[] s = Arrays.copyOfRange(signature, sigOffset + 32, sigOffset + 64);
        RistrettoElement S = Constants.RISTRETTO_GENERATOR_TABLE.multiply(Scalar.fromCanonicalBytes(s));

        CryptoHash hash = BLAKE3.init(64);
        hash.update(r);
        hash.update(publicKey.toByteArray());
        hash.update(message, offset, length);
        Scalar k = Scalar.fromBytesModOrderWide(hash.finish());
        if (!R.equals(negatedElement.multiply(k).add(S))) {
            throw new InvalidSignatureException("Signature mismatch");
        }
    }

    @NotNull RistrettoElement element() {
        return element;
    }
}
