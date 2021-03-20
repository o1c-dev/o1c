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
import dev.o1c.impl.blake3.Blake3RandomBytesGenerator;
import dev.o1c.impl.chacha20.XChaCha20Poly1305CipherKeyFactory;
import dev.o1c.spi.CipherKey;
import dev.o1c.spi.CryptoHash;
import dev.o1c.spi.InvalidSignatureException;
import dev.o1c.spi.PublicKey;
import dev.o1c.spi.SecretKey;
import dev.o1c.util.Validator;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

public class Ristretto255SecretKey extends Ristretto255PublicKey implements SecretKey {
    private final CryptoHash nonceHash = Blake3HashFactory.INSTANCE.initKDF("nonce");
    private final CryptoHash sharedKeyHash = Blake3HashFactory.INSTANCE.initKDF("shared_key");
    private final Scalar scalar;
    private final CryptoHash challenge;

    Ristretto255SecretKey(byte @NotNull [] id, @NotNull Scalar scalar, @NotNull CryptoHash challenge) {
        super(id, Constants.RISTRETTO_GENERATOR_TABLE.multiply(scalar));
        this.scalar = scalar;
        this.challenge = challenge;
    }

    @Override
    public void sign(byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset) {
        Validator.checkBufferArgs(message, offset, length);
        Validator.checkBufferArgs(signature, sigOffset, signatureLength());
        challenge.reset();
        challenge.update(message, offset, length);
        byte[] digest = new byte[64];
        challenge.finish(digest);
        Scalar r = Scalar.fromBytesModOrderWide(digest);
        byte[] R = Constants.RISTRETTO_GENERATOR_TABLE.multiply(r).compress().toByteArray();
        signKeyHash.reset();
        signKeyHash.update(R);
        signKeyHash.update(compressed.toByteArray());
        signKeyHash.update(message, offset, length);
        signKeyHash.finish(digest);
        Scalar k = Scalar.fromBytesModOrderWide(digest);
        Scalar s = k.multiplyAndAdd(scalar, r);
        byte[] S = s.toByteArray();
        System.arraycopy(R, 0, signature, sigOffset, 32);
        System.arraycopy(S, 0, signature, sigOffset + 32, 32);
    }

    @Override
    public void exchangeSecret(@NotNull PublicKey peer, byte @NotNull [] secret, int offset) {
        if (!(peer instanceof Ristretto255PublicKey)) {
            throw new IllegalArgumentException(
                    "Invalid peer public key type; expected Ristretto255PublicKey but got " + peer.getClass());
        }
        Validator.checkBufferArgs(secret, offset, keyLength());
        RistrettoElement product = ((Ristretto255PublicKey) peer).element.multiply(scalar);
        byte[] bytes = product.compress().toByteArray();
        System.arraycopy(bytes, 0, secret, offset, bytes.length);
    }

    @Override
    public void encrypt(
            @NotNull PublicKey recipient, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] plaintext,
            int ptOffset, int ptLength, byte @NotNull [] ciphertext, int ctOffset, byte @NotNull [] tag,
            int tagOffset) {
        Validator.checkBufferArgs(plaintext, ptOffset, ptLength);
        Validator.checkBufferArgs(ciphertext, ctOffset, ptLength);
        throw new UnsupportedOperationException("TODO");
    }

    @Override
    public void decrypt(
            @NotNull PublicKey sender, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] ciphertext,
            int ctOffset, int ctLength, byte @NotNull [] tag, int tagOffset, byte @NotNull [] plaintext, int ptOffset) {
        Validator.checkBufferArgs(ciphertext, ctOffset, ctLength);
        Validator.checkBufferArgs(plaintext, ptOffset, ctLength);
        throw new UnsupportedOperationException("TODO");
    }

    @Override
    public void signcrypt(
            @NotNull PublicKey recipient, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] plaintext,
            int ptOffset, int ptLength, byte @NotNull [] ciphertext, int ctOffset, byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] signature, int sigOffset) {
        if (!(recipient instanceof Ristretto255PublicKey)) {
            throw new IllegalArgumentException("Invalid recipient key type: " + recipient.getClass());
        }
        Validator.checkBufferArgs(plaintext, ptOffset, ptLength);
        Validator.checkBufferArgs(ciphertext, ctOffset, ptLength);
        Validator.checkBufferArgs(signature, sigOffset, signatureLength());
        Ristretto255PublicKey recipientKey = (Ristretto255PublicKey) recipient;

        nonceHash.reset();
        nonceHash.update(scalar.toByteArray());
        nonceHash.update(recipientKey.compressed.toByteArray());
        nonceHash.update(Blake3RandomBytesGenerator.getInstance().generateBytes(32));
        nonceHash.update(plaintext, ptOffset, ptLength);
        byte[] hash = new byte[64];
        nonceHash.finish(hash);

        Scalar r = Scalar.fromBytesModOrderWide(hash);
        byte[] R = Constants.RISTRETTO_GENERATOR_TABLE.multiply(r).compress().toByteArray();
        byte[] k =
                recipientKey.element.multiply(Scalar.fromBits(R).multiplyAndAdd(scalar, r)).compress().toByteArray();
        sharedKeyHash.reset();
        sharedKeyHash.update(k);
        sharedKeyHash.updateRLE(id);
        sharedKeyHash.updateRLE(recipientKey.id);
        sharedKeyHash.updateRLE(context);
        CipherKey cipherKey = XChaCha20Poly1305CipherKeyFactory.INSTANCE.parseKey(sharedKeyHash.finish());

        signKeyHash.reset();
        signKeyHash.update(R);
        signKeyHash.updateRLE(id);
        signKeyHash.updateRLE(recipientKey.id);
        signKeyHash.updateRLE(context);
        cipherKey.encrypt(nonce, context, plaintext, ptOffset, ptLength, ciphertext, ctOffset, tag, tagOffset);
        signKeyHash.update(ciphertext, ctOffset, ptLength);
        signKeyHash.finish(hash);
        Scalar t = Scalar.fromBytesModOrderWide(hash);
        byte[] S = t.multiply(scalar).subtract(r).toByteArray();

        System.arraycopy(R, 0, signature, sigOffset, R.length);
        System.arraycopy(S, 0, signature, sigOffset + R.length, S.length);
    }

    @Override
    public void unsigncrypt(
            @NotNull PublicKey sender, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] ciphertext,
            int ctOffset, int ctLength, byte @NotNull [] tag, int tagOffset, byte @NotNull [] signature, int sigOffset,
            byte @NotNull [] plaintext, int ptOffset) {
        if (!(sender instanceof Ristretto255PublicKey)) {
            throw new IllegalArgumentException("Invalid sender public key type: " + sender.getClass());
        }
        Validator.checkBufferArgs(ciphertext, ctOffset, ctLength);
        Validator.checkBufferArgs(signature, sigOffset, signatureLength());
        Ristretto255PublicKey senderKey = (Ristretto255PublicKey) sender;
        byte[] rBytes = Arrays.copyOfRange(signature, sigOffset, sigOffset + 32);
        byte[] sBytes = Arrays.copyOfRange(signature, sigOffset + 32, sigOffset + 64);
        RistrettoElement R;
        try {
            R = new CompressedRistretto(rBytes).decompress();
        } catch (InvalidEncodingException e) {
            throw new InvalidSignatureException(e);
        }
        Scalar s = Scalar.fromCanonicalBytes(sBytes);
        Scalar reduced = Scalar.fromBits(rBytes);

        byte[] k = senderKey.element.multiply(reduced).add(R).multiply(scalar).compress().toByteArray();
        sharedKeyHash.reset();
        sharedKeyHash.update(k);
        sharedKeyHash.updateRLE(senderKey.id);
        sharedKeyHash.updateRLE(id);
        sharedKeyHash.updateRLE(context);
        CipherKey cipherKey = XChaCha20Poly1305CipherKeyFactory.INSTANCE.parseKey(sharedKeyHash.finish());

        signKeyHash.reset();
        signKeyHash.update(rBytes);
        signKeyHash.updateRLE(senderKey.id);
        signKeyHash.updateRLE(id);
        signKeyHash.updateRLE(context);
        signKeyHash.update(ciphertext, ctOffset, ctLength);
        byte[] tHash = new byte[64];
        signKeyHash.finish(tHash);
        Scalar t = Scalar.fromBytesModOrderWide(tHash);
        if (!senderKey.element.multiply(t).equals(Constants.RISTRETTO_GENERATOR_TABLE.multiply(s).add(R))) {
            throw new InvalidSignatureException("Signature mismatch");
        }
        cipherKey.decrypt(nonce, context, ciphertext, ctOffset, ctLength, tag, tagOffset, plaintext, ptOffset);
    }
}
