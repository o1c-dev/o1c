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

import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

/**
 * Represents the state just prior to either producing an eight word chaining value or any number of output bytes when the
 * {@link Constants#ROOT} flag is set.
 */
class Output {
    private final int[] inputChainingValue;
    private final int[] blockWords;
    private final long counter;
    private final int blockLength;
    private final @Flag int flags;

    Output(int @NotNull [] inputCV, int @NotNull [] blockWords, long counter, int blockLength, @Flag int flags) {
        this.inputChainingValue = inputCV;
        this.blockWords = blockWords;
        this.counter = counter;
        this.blockLength = blockLength;
        this.flags = flags;
    }

    int @NotNull [] chainingValue() {
        return Arrays.copyOf(Blake3Hash.compress(
                inputChainingValue, blockWords, blockLength, counter, flags), 8);
    }

    void rootOutputBytes(byte @NotNull [] out, int offset, int length) {
        int outputBlockCounter = 0;
        while (length > 0) {
            int chunkLength = Math.min(Constants.OUT_LEN * 2, length);
            length -= chunkLength;
            int[] words = Blake3Hash.compress(
                    inputChainingValue, blockWords, blockLength, outputBlockCounter++, flags | Constants.ROOT);
            int wordCounter = 0;
            while (chunkLength > 0) {
                int wordLength = Math.min(Integer.BYTES, chunkLength);
                ByteOps.packIntLE(words[wordCounter++], out, offset, wordLength);
                offset += wordLength;
                chunkLength -= wordLength;
            }
        }
    }
}
