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
import dev.o1c.spi.HashFactory;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;

public enum Blake2bHashFactory implements HashFactory {
    INSTANCE;

    private static final byte[] DERIVE_KEY_CONTEXT = "DeriveKeyContext".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] DERIVE_KEY_SUBTEXT = "DeriveKeySubtext".getBytes(StandardCharsets.US_ASCII);

    @Override
    public @NotNull CryptoHash init() {
        return new Blake2b(new Blake2bDigest());
    }

    @Override
    public @NotNull CryptoHash init(int hashLength) {
        return new Blake2b(new Blake2bDigest(hashLength * Byte.SIZE));
    }

    @Override
    public @NotNull CryptoHash init(byte @NotNull [] key) {
        return new Blake2b(new Blake2bDigest(key));
    }

    @Override
    public @NotNull CryptoHash initKDF(byte @NotNull [] context) {
        Blake2bDigest ctxHash = new Blake2bDigest(null, 64, null, DERIVE_KEY_CONTEXT);
        ctxHash.update(context, 0, context.length);
        byte[] key = new byte[64];
        ctxHash.doFinal(key, 0);
        return new Blake2b(new Blake2bDigest(key, 64, null, DERIVE_KEY_SUBTEXT));
    }

    private static class Blake2b implements CryptoHash {
        private final Blake2bDigest digest;

        private Blake2b(Blake2bDigest digest) {
            this.digest = digest;
        }

        @Override
        public int hashLength() {
            return digest.getDigestSize();
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
            if (length != hashLength()) {
                throw new UnsupportedOperationException("No XOF supported in this mode");
            }
            digest.doFinal(out, offset);
        }
    }
}
