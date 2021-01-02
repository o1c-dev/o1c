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

package dev.o1c.modern.blake2;

import dev.o1c.spi.CryptoHash;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.jetbrains.annotations.NotNull;

public class Blake2bCryptoHash implements CryptoHash {
    private final int hashLength;
    private final Blake2bDigest digest;

    public Blake2bCryptoHash(int hashLength) {
        this.hashLength = hashLength;
        digest = new Blake2bDigest(hashLength * Byte.SIZE);
    }

    @Override
    public int hashLength() {
        return hashLength;
    }

    @Override
    public void reset() {
        digest.reset();
    }

    @Override
    public void update(byte b) {
        digest.update(b);
    }

    @Override
    public void update(byte @NotNull [] in, int offset, int length) {
        digest.update(in, offset, length);
    }

    @Override
    public void finish(byte @NotNull [] out, int offset) {
        digest.doFinal(out, offset);
    }

    @Override
    public void finish(byte @NotNull [] out, int offset, int length) {
        if (length != hashLength) {
            throw new UnsupportedOperationException("XOF not implemented");
        }
        finish(out, offset);
    }
}
