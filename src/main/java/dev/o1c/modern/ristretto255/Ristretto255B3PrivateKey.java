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

import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.Scalar;
import dev.o1c.spi.Certificate;
import dev.o1c.spi.CryptoHash;
import dev.o1c.spi.PrivateKey;
import org.jetbrains.annotations.NotNull;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;

public class Ristretto255B3PrivateKey extends Ristretto255B3Certificate implements PrivateKey {
    private final Scalar scalar;
    private final CryptoHash challenge;

    Ristretto255B3PrivateKey(byte @NotNull [] id, @NotNull Scalar scalar, @NotNull CryptoHash challenge) {
        super(id, Constants.RISTRETTO_GENERATOR_TABLE.multiply(scalar));
        this.scalar = scalar;
        this.challenge = challenge;
    }

    Ristretto255B3PrivateKey(@NotNull Scalar scalar, @NotNull CryptoHash challenge) {
        super(Constants.RISTRETTO_GENERATOR_TABLE.multiply(scalar));
        this.scalar = scalar;
        this.challenge = challenge;
    }

    @Override
    public void sign(
            byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset) {
        if (offset + length > message.length) {
            throw new BufferUnderflowException();
        }
        if (sigOffset + signatureLength() > signature.length) {
            throw new BufferOverflowException();
        }

        challenge.reset();
        challenge.update(message, offset, length);
        byte[] digest = new byte[64];
        challenge.finish(digest);
        Scalar r = Scalar.fromBytesModOrderWide(digest);
        byte[] R = Constants.RISTRETTO_GENERATOR_TABLE.multiply(r).compress().toByteArray();
        CryptoHash hash = BLAKE3.init(64);
        hash.update(R);
        hash.update(publicKey());
        hash.update(message, offset, length);
        Scalar k = Scalar.fromBytesModOrderWide(hash.finish());
        Scalar s = k.multiplyAndAdd(scalar, r);
        byte[] S = s.toByteArray();
        System.arraycopy(R, 0, signature, sigOffset, R.length);
        System.arraycopy(S, 0, signature, sigOffset + R.length, S.length);
    }

    @Override
    public byte @NotNull [] sharedSecret(@NotNull Certificate peer) {
        if (peer instanceof Ristretto255B3Certificate) {
            RistrettoElement peerElement = ((Ristretto255B3Certificate) peer).element();
            return peerElement.multiply(scalar).compress().toByteArray();
        }
        throw new UnsupportedOperationException("Invalid certificate type: " + peer.getClass());
    }
}
