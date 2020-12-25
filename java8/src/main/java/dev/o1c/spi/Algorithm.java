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

import java.security.CryptoPrimitive;

public enum Algorithm {
    ChaCha20Poly1305("ChaCha20-Poly1305", CryptoPrimitive.STREAM_CIPHER, 32, "1.2.840.113549.1.9.16.3.18"),
    X25519("X25519", CryptoPrimitive.KEY_AGREEMENT, 32, "1.3.101.110"),
    X448("X448", CryptoPrimitive.KEY_AGREEMENT, 56, "1.3.101.111"),
    Ed25519("Ed25519", CryptoPrimitive.SIGNATURE, 32, "1.3.101.112"),
    Ed448("Ed448", CryptoPrimitive.SIGNATURE, 57, "1.3.101.113"),
    Argon2i("Argon2i", CryptoPrimitive.KEY_ENCAPSULATION, 32, "TODO");

    private final String algorithm;
    private final CryptoPrimitive cryptoPrimitive;
    private final int keySize;
    // https://www.rfc-editor.org/info/rfc8410
    private final String objectIdentifier;

    Algorithm(String algorithm, CryptoPrimitive cryptoPrimitive, int keySize, String objectIdentifier) {
        this.algorithm = algorithm;
        this.cryptoPrimitive = cryptoPrimitive;
        this.keySize = keySize;
        this.objectIdentifier = objectIdentifier;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public CryptoPrimitive getCryptoPrimitive() {
        return cryptoPrimitive;
    }

    public int getKeySize() {
        return keySize;
    }

    public String getObjectIdentifier() {
        return objectIdentifier;
    }
}
