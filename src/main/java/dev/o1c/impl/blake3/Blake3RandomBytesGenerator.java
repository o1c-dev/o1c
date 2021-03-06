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

package dev.o1c.impl.blake3;

import dev.o1c.spi.Hash;
import dev.o1c.spi.RandomBytesGenerator;
import dev.o1c.spi.SeedGenerator;
import org.jetbrains.annotations.NotNull;

// https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
// https://doi.org/10.6028/NIST.SP.800-90Ar1
public class Blake3RandomBytesGenerator implements RandomBytesGenerator {
    private static final ThreadLocal<Blake3RandomBytesGenerator> CURRENT = new ThreadLocal<>();
    private static final long RESEED_INTERVAL = 1L << 48;
    private Hash hash;
    private long counter;

    public Blake3RandomBytesGenerator() {
        reseed();
    }

    private void reseed() {
        counter = 0;
        byte[] seed = SeedGenerator.getInstance().generateSeed(32);
        hash = Blake3HashFactory.INSTANCE.newKeyedHash(seed);
    }

    private void ratchet() {
        if (++counter == RESEED_INTERVAL) {
            reseed();
        } else {
            byte[] nextKey = new byte[32];
            hash.doFinalize(nextKey);
            hash = Blake3HashFactory.INSTANCE.newKeyedHash(nextKey);
        }
    }

    @Override
    public void generateBytes(byte @NotNull [] out, int offset, int length) {
        // skip over ratchet key
        byte[] skip = new byte[64];
        hash.doFinalize(skip);
        hash.doFinalize(out, offset, length);
        ratchet();
    }

    public static @NotNull Blake3RandomBytesGenerator getInstance() {
        if (CURRENT.get() == null) {
            CURRENT.set(new Blake3RandomBytesGenerator());
        }
        return CURRENT.get();
    }
}
