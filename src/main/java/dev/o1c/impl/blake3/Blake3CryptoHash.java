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

import dev.o1c.spi.CryptoHash;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

/**
 * Implements the <a href="https://github.com/BLAKE3-team/BLAKE3">BLAKE3 hash function</a>.
 *
 * @see <a href="https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs">Rust (reference) implementation</a>
 * @see <a href="https://github.com/ziglang/zig/blob/master/lib/std/crypto/blake3.zig">Zig implementation</a>
 */
// initially refined along this zig revision
// https://github.com/ziglang/zig/blob/6c2e0c2046a4c1d01587cc15ea2f59af32743eb4/lib/std/crypto/blake3.zig
public class Blake3CryptoHash implements CryptoHash {
    private final int[] key;
    private final @Flag int flags;
    private final int defaultHashLength;
    // Space for 54 subtree chaining values: 2^54 * CHUNK_LEN = 2^64
    private final int[][] cvStack = new int[54][];
    private int stackLen;
    private ChunkState state;

    Blake3CryptoHash(int @NotNull [] key, @Flag int flags) {
        this(key, flags, Constants.OUT_LEN);
    }

    Blake3CryptoHash(int @NotNull [] key, @Flag int flags, int defaultHashLength) {
        this.key = key;
        this.flags = flags;
        this.defaultHashLength = defaultHashLength;
        this.state = new ChunkState(key, 0, flags);
    }

    @Override
    public void reset() {
        stackLen = 0;
        Arrays.fill(cvStack, null);
        state = new ChunkState(key, 0, flags);
    }

    @Override
    public int hashLength() {
        return defaultHashLength;
    }

    @Override
    public void update(byte b) {
        inputData(new byte[] { b }, 0, 1);
    }

    @Override
    public void update(byte @NotNull [] in, int offset, int length) {
        inputData(in, offset, length);
    }

    @Override
    public void finish(byte @NotNull [] out, int offset, int length) {
        outputHash(out, offset, length);
    }

    /**
     * Adds input to the hash state. This can be called any number of times.
     *
     * @param in     input data buffer
     * @param offset where in the buffer to read data from
     * @param length how many bytes to read
     */
    void inputData(byte @NotNull [] in, int offset, int length) {
        while (length > 0) {
            // If the current chunk is complete, finalize it and reset the
            // chunk state. More input is coming, so this chunk is not ROOT.
            if (state.length() == Constants.CHUNK_LEN) {
                int[] chunkCV = state.output().chainingValue();
                long totalChunks = state.chunkCounter() + 1;
                addChunkCV(chunkCV, totalChunks);
                state = new ChunkState(key, totalChunks, flags);
            }

            // Compress input bytes into the current chunk state.
            int want = Constants.CHUNK_LEN - state.length();
            int take = Math.min(want, length);
            state.update(in, offset, take);
            offset += take;
            length -= take;
        }
    }

    /**
     * Finalize the hash and write any number of output bytes.
     *
     * @param out    output buffer to write hash data to
     * @param offset where in the buffer to write data
     * @param length how many bytes to generate and write
     */
    void outputHash(byte @NotNull [] out, int offset, int length) {
        // Starting with the Output from the current chunk, compute all the
        // parent chaining values along the right edge of the tree, until we
        // have the root Output.
        Output output = state.output();
        int parentNodesRemaining = stackLen;
        while (parentNodesRemaining-- > 0) {
            int[] parentCV = cvStack[parentNodesRemaining];
            output = parentOutput(parentCV, output.chainingValue(), key, flags);
        }
        output.rootOutputBytes(out, offset, length);
    }

    // Section 5.1.2 of the BLAKE3 spec explains this algorithm in more detail.
    private void addChunkCV(int @NotNull [] firstCV, long totalChunks) {
        // This chunk might complete some subtrees. For each completed subtree,
        // its left child will be the current top entry in the CV stack, and
        // its right child will be the current value of `newCV`. Pop each left
        // child off the stack, merge it with `newCV`, and overwrite `newCV`
        // with the result. After all these merges, push the final value of
        // `newCV` onto the stack. The number of completed subtrees is given
        // by the number of trailing 0-bits in the new total number of chunks.
        int[] newCV = firstCV;
        long chunkCounter = totalChunks;
        while ((chunkCounter & 1) == 0) {
            newCV = parentChainingValue(popCV(), newCV, key, flags);
            chunkCounter >>= 1;
        }
        pushCV(newCV);
    }

    private void pushCV(int @NotNull [] cv) {
        cvStack[stackLen++] = cv;
    }

    private int @NotNull [] popCV() {
        return cvStack[--stackLen];
    }

    static int @NotNull [] compress(
            int @NotNull [] chainingValue, int @NotNull [] blockWords, int blockLength, long counter,
            @Flag int flags) {
        int[] state = Arrays.copyOf(chainingValue, 16);
        System.arraycopy(Constants.IV, 0, state, 8, 4);
        state[12] = (int) counter;
        state[13] = (int) (counter >> Integer.SIZE);
        state[14] = blockLength;
        state[15] = flags;
        for (int i = 0; i < 7; i++) {
            byte[] schedule = Constants.MSG_SCHEDULE[i];
            round(state, blockWords, schedule);
        }
        for (int i = 0; i < 8; i++) {
            state[i] ^= state[i + 8];
            state[i + 8] ^= chainingValue[i];
        }
        return state;
    }

    private static Output parentOutput(int[] leftChildCV, int[] rightChildCV, int[] key, @Flag int flags) {
        int[] blockWords = Arrays.copyOf(leftChildCV, 16);
        System.arraycopy(rightChildCV, 0, blockWords, 8, 8);
        flags |= Constants.PARENT;
        return new Output(key.clone(), blockWords, 0, Constants.BLOCK_LEN, flags);
    }

    private static int[] parentChainingValue(int[] leftChildCV, int[] rightChildCV, int[] key, @Flag int flags) {
        return parentOutput(leftChildCV, rightChildCV, key, flags).chainingValue();
    }

    private static void round(int[] state, int[] msg, byte[] schedule) {
        // Mix the columns.
        g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
        g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
        g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
        g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);

        // Mix the diagonals.
        g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
        g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
        g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
        g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
    }

    // The mixing function, G, which mixes either a column or a diagonal.
    private static void g(int[] state, int a, int b, int c, int d, int mx, int my) {
        state[a] += state[b] + mx;
        state[d] = Integer.rotateRight(state[d] ^ state[a], 16);
        state[c] += state[d];
        state[b] = Integer.rotateRight(state[b] ^ state[c], 12);
        state[a] += state[b] + my;
        state[d] = Integer.rotateRight(state[d] ^ state[a], 8);
        state[c] += state[d];
        state[b] = Integer.rotateRight(state[b] ^ state[c], 7);
    }
}
