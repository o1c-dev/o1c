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

package dev.o1c.modern.blake3;

import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

import java.util.Arrays;

class ChunkState {
    private int @NotNull [] chainingValue;
    private final long chunkCounter;
    private final @Flag int flags;

    private final byte[] block = new byte[Constants.BLOCK_LEN];
    private @Range(from = 0, to = Constants.BLOCK_LEN) int blockLength;
    private int blocksCompressed;

    ChunkState(int @NotNull [] key, long chunkCounter, @Flag int flags) {
        this.chainingValue = key;
        this.chunkCounter = chunkCounter;
        this.flags = flags;
    }

    int length() {
        return Constants.BLOCK_LEN * blocksCompressed + blockLength;
    }

    @Flag
    int startFlag() {
        return blocksCompressed == 0 ? Constants.CHUNK_START : 0;
    }

    long chunkCounter() {
        return chunkCounter;
    }

    void update(byte @NotNull [] input, int offset, int length) {
        while (length > 0) {
            if (blockLength == Constants.BLOCK_LEN) {
                // If the block buffer is full, compress it and clear it. More
                // input is coming, so this compression is not CHUNK_END.
                int[] blockWords = ByteOps.unpackIntsLE(block, 0, 16);
                chainingValue = Arrays.copyOf(Blake3CryptoHash.compress(
                        chainingValue, blockWords, Constants.BLOCK_LEN, chunkCounter, flags | startFlag()), 8);
                blocksCompressed++;
                blockLength = 0;
                ByteOps.overwriteWithZeroes(block);
            }

            int want = Constants.BLOCK_LEN - blockLength;
            int take = Math.min(want, length);
            System.arraycopy(input, offset, block, blockLength, take);
            blockLength += take;
            offset += take;
            length -= take;
        }
    }

    Output output() {
        int[] blockWords = ByteOps.unpackIntsLE(block, 0, 16);
        int flags = this.flags | startFlag() | Constants.CHUNK_END;
        return new Output(chainingValue, blockWords, chunkCounter, blockLength, flags);
    }
}
