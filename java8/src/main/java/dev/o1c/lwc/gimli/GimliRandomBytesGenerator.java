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
 *
 * SPDX-License-Identifier: ISC
 */

package dev.o1c.lwc.gimli;

import dev.o1c.primitive.EntropyChannel;
import dev.o1c.primitive.RandomBytesGenerator;
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

// https://doi.org/10.6028/NIST.SP.800-90Ar1
// implementation comparable to CTR_DRBG, but also similar to HMAC_DRBG since Gimli is versatile
// https://csrc.nist.gov/Projects/Random-Bit-Generation
// provides a 128-bit security level DRBG
public final class GimliRandomBytesGenerator implements RandomBytesGenerator {
    private static final ThreadLocal<GimliRandomBytesGenerator> CURRENT = new ThreadLocal<>();
    private static final int SEED_SIZE = 56;
    private final Gimli state = new Gimli();
    private long reseedCounter;
    private long nonce;
    // TODO: need a personalization string to XOR into the entropy input

    public GimliRandomBytesGenerator() {
        reseed();
    }

    @Override
    public void fill(@NotNull ByteBuffer dst) {
        state.permute();
        state.squeeze(dst);
        ratchet();
    }

    private void ratchet() {
        state.ratchet(nonce);
        nonce++;
        if (nonce == reseedCounter) {
            reseed();
        }
    }

    private void reseed() {
        byte[] seed = new byte[SEED_SIZE];
        EntropyChannel.getInstance().read(seed);
        for (int i = 0; i < 12; i++) {
            state.absorb(i, ByteOps.unpackIntLE(seed, i * Integer.BYTES));
        }
        reseedCounter = nonce = ByteOps.unpackLongLE(seed, 48);
    }

    public static GimliRandomBytesGenerator getInstance() {
        if (CURRENT.get() == null) {
            CURRENT.set(new GimliRandomBytesGenerator());
        }
        return CURRENT.get();
    }
}
