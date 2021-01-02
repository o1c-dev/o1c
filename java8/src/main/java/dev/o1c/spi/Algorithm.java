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

package dev.o1c.spi;

public enum Algorithm {
    ChaCha20Poly1305("ChaCha20-Poly1305", 32, "1.2.840.113549.1.9.16.3.18"),
    X25519("X25519", 32, "1.3.101.110"),
    X448("X448", 56, "1.3.101.111");

    private final String algorithm;
    private final int keySize;
    // https://www.rfc-editor.org/info/rfc8410
    private final String objectIdentifier;

    Algorithm(String algorithm, int keySize, String objectIdentifier) {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.objectIdentifier = objectIdentifier;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getKeySize() {
        return keySize;
    }

    public String getObjectIdentifier() {
        return objectIdentifier;
    }
}
