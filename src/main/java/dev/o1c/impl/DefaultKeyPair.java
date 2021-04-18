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
import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.InvalidEncodingException;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.Scalar;
import dev.o1c.KeyPair;
import dev.o1c.PublicKey;
import dev.o1c.impl.blake3.Blake3HashFactory;
import dev.o1c.impl.blake3.Blake3RandomBytesGenerator;
import dev.o1c.spi.Hash;
import dev.o1c.spi.InvalidKeyException;
import dev.o1c.spi.InvalidSignatureException;
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

class DefaultKeyPair extends DefaultPublicKey implements KeyPair {
    private final Scalar scalar;
    private final Hash challenge;

    DefaultKeyPair(@NotNull Scalar scalar, @NotNull Hash challenge) {
        super(Constants.RISTRETTO_GENERATOR_TABLE.multiply(scalar));
        this.scalar = scalar;
        this.challenge = challenge;
    }

    @Override
    public byte @NotNull [] box(@NotNull PublicKey recipient, byte @NotNull [] message, byte @NotNull [] context) {
        if (!(recipient instanceof DefaultPublicKey)) {
            throw new InvalidKeyException("Recipient key incompatible with this key");
        }
        DefaultPublicKey peer = (DefaultPublicKey) recipient;
        Hash hash = Blake3HashFactory.INSTANCE.newHash();
        hash.update(exchangeSecret(peer));
        hash.update(compressedElement.toByteArray());
        hash.update(peer.compressedElement.toByteArray());
        // TODO: consider hashing in context as well (like in signcryption)
        DefaultSecretKey key = new DefaultSecretKey(hash.doFinalize());
        return key.box(message, context);
    }

    @Override
    public byte @NotNull [] openBox(@NotNull PublicKey sender, byte @NotNull [] box, byte @NotNull [] context) {
        if (!(sender instanceof DefaultPublicKey)) {
            throw new InvalidKeyException("Sender key incompatible with this key");
        }
        DefaultPublicKey peer = (DefaultPublicKey) sender;
        Hash hash = Blake3HashFactory.INSTANCE.newHash();
        hash.update(exchangeSecret(peer));
        hash.update(peer.compressedElement.toByteArray());
        hash.update(compressedElement.toByteArray());
        DefaultSecretKey key = new DefaultSecretKey(hash.doFinalize());
        return key.openBox(box, context);
    }

    private byte[] exchangeSecret(DefaultPublicKey peer) {
        return peer.element.multiply(scalar).compress().toByteArray();
    }

    @Override
    public byte @NotNull [] sign(byte @NotNull [] message) {
        challenge.reset();
        challenge.update(message);
        byte[] digest = new byte[64];
        challenge.doFinalize(digest);
        Scalar r = Scalar.fromBytesModOrderWide(digest);
        byte[] R = Constants.RISTRETTO_GENERATOR_TABLE.multiply(r).compress().toByteArray();
        signingHash.reset();
        signingHash.update(R);
        signingHash.update(compressedElement.toByteArray());
        signingHash.update(message);
        byte[] hash = signingHash.doFinalize();
        Scalar k = Scalar.fromBytesModOrderWide(hash);
        Scalar s = k.multiplyAndAdd(scalar, r);
        byte[] S = s.toByteArray();
        return ByteOps.concat(R, message, S);
    }

    /*
    given sender keys W_a = w_a * G with id_a, and recipient keys W_b = w_b * G with id_b
    1. validate recipient certificate if used
    2. select random scalar r
    3. compute R = r * G where G is the generator element; let R = (x_r, y_r) in compressed x/y coordinates
    4. given key size in bits f (256 in ed25519), let x_r' = 2^ceil(f/2) + (x_r % 2^ceil(f/2))
    (or x_r' = 2^128 + (x_r % 2^128)
    compute K = (r + x_r' * w_a) * W_b, where K = (x_K, y_K) in compressed coordinates
    if K is the identity element, retry back to #2.
    let session key k = H(x_K || id_a || y_K || id_b)
    5. compute ciphertext C = E_k(M)
    6. compute t = H(C || x_r || id_a || y_r || id_b)
    compute s = (t * w_a - r) % n
    7. send signcrypted (R, C, s)
     */
    @Override
    public byte @NotNull [] sealedBox(@NotNull PublicKey recipient, byte @NotNull [] message, byte @NotNull [] context) {
        if (!(recipient instanceof DefaultPublicKey)) {
            throw new InvalidKeyException("Recipient key incompatible with this key");
        }
        DefaultPublicKey peer = (DefaultPublicKey) recipient;
        Hash nonceHash = Blake3HashFactory.INSTANCE.newKeyDerivationFunction("nonce");
        nonceHash.update(scalar.toByteArray());
        nonceHash.update(peer.compressedElement.toByteArray());
        nonceHash.update(Blake3RandomBytesGenerator.getInstance().generateBytes(32));
        nonceHash.update(message);
        byte[] hash = new byte[64];
        nonceHash.doFinalize(hash);

        Scalar r = Scalar.fromBytesModOrderWide(hash);
        byte[] R = Constants.RISTRETTO_GENERATOR_TABLE.multiply(r).compress().toByteArray();
        byte[] k = peer.element.multiply(Scalar.fromBits(R).multiplyAndAdd(scalar, r)).compress().toByteArray();
        Hash sharedKeyHash = Blake3HashFactory.INSTANCE.newKeyDerivationFunction("shared_key");
        sharedKeyHash.update(k);
        sharedKeyHash.update(compressedElement.toByteArray());
        sharedKeyHash.update(peer.compressedElement.toByteArray());
        sharedKeyHash.updateRLE(context);
        DefaultSecretKey key = new DefaultSecretKey(sharedKeyHash.doFinalize());

        Hash signKeyHash = Blake3HashFactory.INSTANCE.newKeyDerivationFunction("sign_key");
        signKeyHash.update(R);
        signKeyHash.update(compressedElement.toByteArray());
        signKeyHash.update(peer.compressedElement.toByteArray());
        signKeyHash.updateRLE(context);
        byte[] box = key.box(message, context);
        signKeyHash.update(box, key.nonceLength(), message.length);
        signKeyHash.doFinalize(hash);
        Scalar t = Scalar.fromBytesModOrderWide(hash);
        byte[] S = t.multiply(scalar).subtract(r).toByteArray();
        return ByteOps.concat(R, box, S);
    }

    /*
    given signcrypted message (R, C, s)
    compute K = w_b * (R + x_r' * W_a) = (x_K, y_K)
    compute k = H(x_K || id_a || y_K || id_b)
    decrypt M = D_k(C)
    compute t = H(C || x_r || id_a || y_r || id_b)
    verify that s * G + R = t * W_a
     */
    @Override
    public byte @NotNull [] openSealedBox(@NotNull PublicKey sender, byte @NotNull [] sealedBox, byte @NotNull [] context) {
        if (!(sender instanceof DefaultPublicKey)) {
            throw new InvalidKeyException("Sender key incompatible with this key");
        }
        if (sealedBox.length < 64) {
            throw new InvalidSignatureException("Sealed box data too short to have a signature");
        }
        DefaultPublicKey peer = (DefaultPublicKey) sender;
        byte[] r = Arrays.copyOf(sealedBox, 32);
        RistrettoElement R;
        try {
            R = new CompressedRistretto(r).decompress();
        } catch (InvalidEncodingException e) {
            throw new InvalidSignatureException(e);
        }
        Scalar reduced = Scalar.fromBits(r);
        byte[] s = Arrays.copyOfRange(sealedBox, sealedBox.length - 32, sealedBox.length);
        RistrettoElement check = Constants.RISTRETTO_GENERATOR_TABLE.multiply(Scalar.fromCanonicalBytes(s)).add(R);

        byte[] k = peer.element.multiply(reduced).add(R).multiply(scalar).compress().toByteArray();
        Hash sharedKeyHash = Blake3HashFactory.INSTANCE.newKeyDerivationFunction("shared_key");
        sharedKeyHash.update(k);
        sharedKeyHash.update(peer.compressedElement.toByteArray());
        sharedKeyHash.update(compressedElement.toByteArray());
        sharedKeyHash.updateRLE(context);
        DefaultSecretKey key = new DefaultSecretKey(sharedKeyHash.doFinalize());

        Hash signKeyHash = Blake3HashFactory.INSTANCE.newKeyDerivationFunction("sign_key");
        signKeyHash.update(r);
        signKeyHash.update(peer.compressedElement.toByteArray());
        signKeyHash.update(compressedElement.toByteArray());
        signKeyHash.updateRLE(context);
        signKeyHash.update(sealedBox, 32 + key.nonceLength(), sealedBox.length - 64 - key.nonceLength() - key
                .tagLength());
        byte[] tHash = new byte[64];
        signKeyHash.doFinalize(tHash);
        Scalar t = Scalar.fromBytesModOrderWide(tHash);
        if (!check.equals(peer.element.multiply(t))) {
            throw new InvalidSignatureException("Signature mismatch");
        }

        return key.openBox(Arrays.copyOfRange(sealedBox, 32, sealedBox.length - 32), context);
    }
}
