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
import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.InvalidEncodingException;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.Scalar;
import dev.o1c.impl.blake3.Blake3HashFactory;
import dev.o1c.spi.Hash;
import dev.o1c.spi.InvalidKeyException;
import dev.o1c.spi.PublicKey;
import dev.o1c.util.Validator;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public class Ristretto255PublicKey implements PublicKey {
    final Hash signKeyHash = Blake3HashFactory.INSTANCE.initKDF("sign_key");
    final byte[] id;
    final RistrettoElement element;
    private final RistrettoElement negatedElement; // TODO: this should be lazily initialized when first verifying
    final CompressedRistretto compressed;

    Ristretto255PublicKey(byte @NotNull [] id, @NotNull RistrettoElement element) {
        this.id = id;
        this.element = element;
        negatedElement = element.negate();
        compressed = element.compress();
    }

    Ristretto255PublicKey(byte @NotNull [] id, @NotNull CompressedRistretto compressed) {
        this.id = id;
        this.compressed = compressed;
        try {
            element = compressed.decompress();
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
    public int keyLength() {
        return 32;
    }

    @Override
    public int signatureLength() {
        return 64;
    }

    // TODO: add a validation for signcrypted messages

    @Override
    public boolean isValidSignature(byte @NotNull [] signature, byte @NotNull [] message, int offset, int length) {
        Validator.checkBufferArgs(message, offset, length);
        if (signature.length != signatureLength()) {
            return false;
        }
        byte[] r = Arrays.copyOf(signature, 32);
        byte[] s = Arrays.copyOfRange(signature, 32, 64);
        RistrettoElement R;
        RistrettoElement S;
        try {
            R = new CompressedRistretto(r).decompress();
            S = Constants.RISTRETTO_GENERATOR_TABLE.multiply(Scalar.fromCanonicalBytes(s));
        } catch (InvalidEncodingException | IllegalArgumentException ignored) {
            return false;
        }
        signKeyHash.reset();
        signKeyHash.update(r);
        signKeyHash.update(compressed.toByteArray());
        signKeyHash.update(message, offset, length);
        byte[] hash = new byte[64];
        signKeyHash.finish(hash);
        Scalar k = Scalar.fromBytesModOrderWide(hash);
        RistrettoElement checkR = negatedElement.multiply(k).add(S);
        return R.equals(checkR);
    }
}
