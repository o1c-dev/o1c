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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyPairCodec extends SecurityFactory<KeyPair> {
    @Override
    default KeyPair create() {
        return generateKeyPair();
    }

    KeyPair generateKeyPair();

    byte[] encodeKey(PublicKey key);

    byte[] encodeKey(PrivateKey key);

    PublicKey decodePublicKey(byte[] keyData);

    PrivateKey decodePrivateKey(byte[] keyData);

    static KeyPairCodec getInstance(Algorithm algorithm) {
        return SecurityFactory.getInstance(KeyPairCodec.class, codec -> algorithm == codec.getAlgorithm(),
                () -> "No KeyPairCodec providers found for " + algorithm);
    }
}
