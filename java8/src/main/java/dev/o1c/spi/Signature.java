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

import java.security.PrivateKey;
import java.security.PublicKey;

public interface Signature {
    KeyPairCodec getKeyPairCodec();

    byte[] calculateSignature(PrivateKey key, byte[] data);

    boolean verifySignature(PublicKey key, byte[] data, byte[] signature);

    default byte[] calculateSignature(byte[] privateKey, byte[] data) {
        return calculateSignature(getKeyPairCodec().decodePrivateKey(privateKey), data);
    }

    default boolean verifySignature(byte[] publicKey, byte[] data, byte[] signature) {
        return verifySignature(getKeyPairCodec().decodePublicKey(publicKey), data, signature);
    }

    static Signature getInstance(Algorithm algorithm) {
        return SecurityFactory.getInstance(SignatureFactory.class, factory -> algorithm == factory.getAlgorithm(),
                () -> "No SignatureFactory providers found for " + algorithm).create();
    }
}
