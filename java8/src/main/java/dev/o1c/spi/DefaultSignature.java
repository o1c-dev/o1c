/*
 * ISC License
 *
 * Copyright (c) 2020, Matt Sicker
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
 */

package dev.o1c.spi;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.function.Supplier;

class DefaultSignature implements Signature {
    private final KeyPairCodec keyPairCodec;
    private final Supplier<java.security.Signature> signatureSupplier;

    DefaultSignature(KeyPairCodec keyPairCodec, Supplier<java.security.Signature> signatureSupplier) {
        this.keyPairCodec = keyPairCodec;
        this.signatureSupplier = signatureSupplier;
    }

    @Override
    public KeyPairCodec getKeyPairCodec() {
        return keyPairCodec;
    }

    @Override
    public byte[] calculateSignature(PrivateKey key, byte[] data) {
        java.security.Signature signature = signatureSupplier.get();
        try {
            signature.initSign(key);
            signature.update(data);
            return signature.sign();
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean verifySignature(PublicKey key, byte[] data, byte[] signature) {
        java.security.Signature verification = signatureSupplier.get();
        try {
            verification.initVerify(key);
            verification.update(data);
            return verification.verify(signature);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }
}
