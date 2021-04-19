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
import dev.o1c.PublicKey;
import dev.o1c.impl.blake3.Blake3HashFactory;
import dev.o1c.spi.Hash;
import dev.o1c.spi.InvalidKeyException;
import dev.o1c.spi.InvalidSignatureException;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

class DefaultPublicKey implements PublicKey {
    private static final int SIGNATURE_LENGTH = 64;

    final Hash signingHash = Blake3HashFactory.INSTANCE.newHash(SIGNATURE_LENGTH);
    final RistrettoElement element;
    final CompressedRistretto compressedElement;
    private final RistrettoElement negatedElement;

    DefaultPublicKey(@NotNull RistrettoElement element) {
        this.element = element;
        compressedElement = element.compress();
        negatedElement = element.negate();
    }

    DefaultPublicKey(@NotNull CompressedRistretto compressedElement) {
        this.compressedElement = compressedElement;
        try {
            element = compressedElement.decompress();
        } catch (InvalidEncodingException e) {
            throw new InvalidKeyException(e);
        }
        negatedElement = element.negate();
    }

    @Override
    public byte @NotNull [] openSignedMessage(byte @NotNull [] signedMessage) {
        int length = signedMessage.length;
        if (length < SIGNATURE_LENGTH) {
            throw new InvalidSignatureException("Signed message is too short to have a signature");
        }
        byte[] r = Arrays.copyOfRange(signedMessage, 0, 32);
        RistrettoElement R;
        try {
            R = new CompressedRistretto(r).decompress();
        } catch (InvalidEncodingException e) {
            throw new InvalidSignatureException(e);
        }

        Hash signingHash = Blake3HashFactory.INSTANCE.newHash(SIGNATURE_LENGTH);
        signingHash.update(r);
        signingHash.update(compressedElement.toByteArray());
        signingHash.update(signedMessage, 32, length - SIGNATURE_LENGTH);
        byte[] hash = signingHash.doFinalize();
        Scalar k = Scalar.fromBytesModOrderWide(hash);

        byte[] s = Arrays.copyOfRange(signedMessage, length - 32, length);
        RistrettoElement S;
        try {
            S = Constants.RISTRETTO_GENERATOR_TABLE.multiply(Scalar.fromCanonicalBytes(s));
        } catch (IllegalArgumentException e) {
            throw new InvalidSignatureException(e);
        }

        RistrettoElement checkR = negatedElement.multiply(k).add(S);
        if (!R.equals(checkR)) {
            throw new InvalidSignatureException("Signature mismatch");
        }
        return Arrays.copyOfRange(signedMessage, 32, length - 32);
    }

    @Override
    public void validateSealedBox(@NotNull PublicKey sender, byte @NotNull [] sealedBox, byte @NotNull [] context) {
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
        byte[] s = Arrays.copyOfRange(sealedBox, sealedBox.length - 32, sealedBox.length);
        RistrettoElement check = Constants.RISTRETTO_GENERATOR_TABLE.multiply(Scalar.fromCanonicalBytes(s)).add(R);
        Hash signKeyHash = Blake3HashFactory.INSTANCE.newKeyDerivationFunction("sign_key");
        signKeyHash.update(r);
        signKeyHash.update(peer.compressedElement.toByteArray());
        signKeyHash.update(compressedElement.toByteArray());
        signKeyHash.updateRLE(context);
        signKeyHash.update(sealedBox, 32 + 24, sealedBox.length - SIGNATURE_LENGTH - 24 - 16);
        byte[] tHash = new byte[64];
        signKeyHash.doFinalize(tHash);
        Scalar t = Scalar.fromBytesModOrderWide(tHash);
        if (!check.equals(peer.element.multiply(t))) {
            throw new InvalidSignatureException("Signature mismatch");
        }
    }
}
