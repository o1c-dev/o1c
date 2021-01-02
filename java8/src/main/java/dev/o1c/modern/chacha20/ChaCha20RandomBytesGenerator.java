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

package dev.o1c.modern.chacha20;

import dev.o1c.spi.RandomBytesGenerator;
import dev.o1c.spi.SeedGenerator;
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;

// https://doi.org/10.6028/NIST.SP.800-90Ar1
// based on CTR_DRBG
public class ChaCha20RandomBytesGenerator implements RandomBytesGenerator {
    private static final int BLOCK_LENGTH = 64;
    private static final int SEED_LENGTH = 48; // key + nonce + counter
    private static final long RESEED_INTERVAL = 1L << 48;
    private static final ThreadLocal<ChaCha20RandomBytesGenerator> CURRENT = new ThreadLocal<>();

    private final int[] state = new int[16];
    private long counter;

    public ChaCha20RandomBytesGenerator() {
        ByteOps.unpackIntsLE("expand 32-byte k".getBytes(StandardCharsets.US_ASCII), 0, 4, state, 0);
        reseed();
    }

    @Override
    public byte @NotNull [] generateBytes(int nrBytes) {
        byte[] bytes = new byte[nrBytes];
        int offset = 0;
        while (nrBytes > 0) {
            ChaCha20.permute(state);
            // output keystream block
            int length = Math.min(BLOCK_LENGTH, nrBytes);
            int nrInts = length / Integer.BYTES;
            ByteOps.packIntsLE(state, 0, nrInts, bytes, offset);
            int remaining = length % Integer.BYTES;
            if (remaining > 0) {
                ByteOps.packIntLE(state[nrInts], bytes, length - remaining, remaining);
            }
            offset += length;
            nrBytes -= length;
            // advance counter
            if (++state[12] == 0) {
                ++state[13];
            }
        }
        ratchet();
        return bytes;
    }

    private void reseed() {
        counter = 0;
        byte[] seed = SeedGenerator.getInstance().generateSeed(SEED_LENGTH);
        for (int i = 0; i < 12; i++) {
            state[i + 4] ^= ByteOps.unpackIntLE(seed, i * Integer.BYTES);
        }
        ByteOps.unpackIntsLE(seed, 0, 12, state, 0);
    }

    private void ratchet() {
        state[0] = (int) counter;
        state[1] = (int) (counter >> Integer.SIZE);
        state[2] = 0;
        state[3] = 0;
        ChaCha20.permute(state);
        if (++counter == RESEED_INTERVAL) {
            reseed();
        }
    }

    public static @NotNull ChaCha20RandomBytesGenerator getInstance() {
        if (CURRENT.get() == null) {
            CURRENT.set(new ChaCha20RandomBytesGenerator());
        }
        return CURRENT.get();
    }
}
