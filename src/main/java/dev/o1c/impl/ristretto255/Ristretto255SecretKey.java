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

import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.Scalar;
import dev.o1c.spi.CipherSession;
import dev.o1c.spi.CryptoHash;
import dev.o1c.spi.PublicKey;
import dev.o1c.spi.SecretKey;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public class Ristretto255SecretKey extends Ristretto255PublicKey implements SecretKey {
    private final Scalar scalar;
    private final CryptoHash challenge;

    Ristretto255SecretKey(byte @NotNull [] id, @NotNull Scalar scalar, @NotNull CryptoHash challenge) {
        super(id, Constants.RISTRETTO_GENERATOR_TABLE.multiply(scalar));
        this.scalar = scalar;
        this.challenge = challenge;
    }

    @Override
    public byte @NotNull [] sign(byte @NotNull [] message, int offset, int length) {
        challenge.reset();
        challenge.update(message, offset, length);
        byte[] digest = new byte[64];
        challenge.finish(digest);
        Scalar r = Scalar.fromBytesModOrderWide(digest);
        byte[] R = Constants.RISTRETTO_GENERATOR_TABLE.multiply(r).compress().toByteArray();
        CryptoHash hash = Ristretto255KeyFactory.BLAKE3.init(64);
        hash.update(R);
        hash.update(compressed.toByteArray());
        hash.update(message, offset, length);
        Scalar k = Scalar.fromBytesModOrderWide(hash.finish());
        Scalar s = k.multiplyAndAdd(scalar, r);
        byte[] S = s.toByteArray();
        byte[] signature = new byte[64];
        System.arraycopy(R, 0, signature, 0, 32);
        System.arraycopy(S, 0, signature, 32, 32);
        return signature;
    }

    @Override
    public void encrypt(
            @NotNull PublicKey recipient, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] plaintext,
            int ptOffset, int ptLength, byte @NotNull [] ciphertext, int ctOffset, byte @NotNull [] tag, int tagOffset) {
        throw new UnsupportedOperationException("TODO");
    }

    @Override
    public void decrypt(
            @NotNull PublicKey sender, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] ciphertext,
            int ctOffset, int ctLength, byte @NotNull [] tag, int tagOffset, byte @NotNull [] plaintext, int ptOffset) {
        throw new UnsupportedOperationException("TODO");
    }

    @Override
    public void signcrypt(
            @NotNull PublicKey recipient, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] plaintext,
            int ptOffset, int ptLength, byte @NotNull [] ciphertext, int ctOffset, byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] signature, int sigOffset) {
        throw new UnsupportedOperationException("TODO");
    }

    @Override
    public void unsigncrypt(
            @NotNull PublicKey sender, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] ciphertext,
            int ctOffset, int ctLength, byte @NotNull [] tag, int tagOffset, byte @NotNull [] signature, int sigOffset,
            byte @NotNull [] plaintext, int ptOffset) {
        throw new UnsupportedOperationException("TODO");
    }

    @Override
    public @NotNull CipherSession exchangeWithServer(@NotNull PublicKey serverKey) {
        if (!(serverKey instanceof Ristretto255PublicKey)) {
            throw new IllegalArgumentException("Invalid server public key type: " + serverKey.getClass());
        }
        Ristretto255PublicKey key = (Ristretto255PublicKey) serverKey;
        // TODO: determine if keyed hash or KDF hash could be more appropriate
        // this kx derivation is currently based on libsodium switching blake2b with blake3 and curve25519 with ristretto255
        CryptoHash hash = Ristretto255KeyFactory.BLAKE3.init(64);
        hash.update(key.element().multiply(scalar).compress().toByteArray());
        hash.update(compressed.toByteArray());
        hash.update(key.compressed.toByteArray());
        byte[] keys = hash.finish();
        byte[] rx = Arrays.copyOf(keys, 32);
        byte[] tx = Arrays.copyOfRange(keys, 32, 64);
        return new CipherSession(rx, tx);
    }

    @Override
    public @NotNull CipherSession exchangeWithClient(@NotNull PublicKey clientKey) {
        if (!(clientKey instanceof Ristretto255PublicKey)) {
            throw new IllegalArgumentException("Invalid client public key type: " + clientKey.getClass());
        }
        Ristretto255PublicKey key = (Ristretto255PublicKey) clientKey;
        CryptoHash hash = Ristretto255KeyFactory.BLAKE3.init(64);
        hash.update(key.element().multiply(scalar).compress().toByteArray());
        hash.update(key.compressed.toByteArray());
        hash.update(compressed.toByteArray());
        byte[] keys = hash.finish();
        byte[] tx = Arrays.copyOf(keys, 32);
        byte[] rx = Arrays.copyOfRange(keys, 32, 64);
        return new CipherSession(rx, tx);
    }
}
