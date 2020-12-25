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

package dev.o1c.i2p;

import dev.o1c.spi.KeyPairCodec;
import dev.o1c.spi.Signature;
import net.i2p.crypto.eddsa.EdDSAEngine;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

class Ed25519Signature implements Signature {
    private final KeyPairCodec keyPairCodec;

    Ed25519Signature(KeyPairCodec keyPairCodec) {
        this.keyPairCodec = keyPairCodec;
    }

    @Override
    public KeyPairCodec getKeyPairCodec() {
        return keyPairCodec;
    }

    @Override
    public byte[] calculateSignature(PrivateKey key, byte[] data) {
        EdDSAEngine engine = new EdDSAEngine();
        try {
            engine.initSign(key);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
        try {
            return engine.signOneShot(data);
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean verifySignature(PublicKey key, byte[] data, byte[] signature) {
        EdDSAEngine engine = new EdDSAEngine();
        try {
            engine.initVerify(key);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
        try {
            return engine.verifyOneShot(data, signature);
        } catch (SignatureException e) {
            throw new IllegalStateException(e);
        }
    }
}
