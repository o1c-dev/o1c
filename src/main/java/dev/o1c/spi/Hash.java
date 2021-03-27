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

import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

/**
 * Provides cryptographic hashes of a sequence of bytes. Hashes are one-way functions that take an essentially
 * arbitrary number of input bytes and calculate finite output bytes in such a way that any changes in the input bytes
 * will cause fairly large differences in the output bytes.
 */
public interface Hash {

    /**
     * Returns the default hash length output by this instance.
     */
    int hashLength();

    /**
     * Resets the state of this instance to begin calculating a fresh hash.
     */
    void reset();

    /**
     * Updates the state of this hash with the provided byte.
     */
    void update(byte b);

    /**
     * Updates the state of this hash with the provided input byte array.
     */
    default void update(byte @NotNull [] in) {
        update(in, 0, in.length);
    }

    /**
     * Updates the state of this hash with the provided array slice.
     *
     * @param in     data to hash into this state
     * @param offset where to begin reading data
     * @param length how many bytes to hash
     */
    void update(byte @NotNull [] in, int offset, int length);

    /**
     * Updates the state of this hash using a runtime length encoded (RLE) buffer. This encodes the length of the buffer
     * as a little endian 32-bit integer followed by the contents of the buffer. This is provided for convenience for
     * creating other primitives.
     *
     * @param buffer data to hash preceded by its data length encoded as a 32-bit little endian integer
     */
    default void updateRLE(byte @NotNull [] buffer) {
        byte[] length = new byte[Integer.BYTES];
        ByteOps.packIntLE(buffer.length, length, 0);
        update(length);
        update(buffer);
    }

    /**
     * Finalizes this hash state into the provided array slice. This allows for extensible output functions when the
     * provided length is not the same as the {@linkplain #hashLength() default hash length}.
     *
     * @param out    destination array to write hash output to
     * @param offset where to begin writing hash output
     * @param length how many bytes to output
     */
    void doFinalize(byte @NotNull [] out, int offset, int length);

    /**
     * Finalizes this hash state into the provided array and offset with the
     * {@linkplain #hashLength() default hash length}.
     *
     * @param out    destination array to write hash output to
     * @param offset where to begin writing hash output
     */
    default void doFinalize(byte @NotNull [] out, int offset) {
        doFinalize(out, offset, hashLength());
    }

    /**
     * Finalizes this hash state into the provided array.
     *
     * @param out destination array to write hash output to
     */
    default void doFinalize(byte @NotNull [] out) {
        doFinalize(out, 0, out.length);
    }

    /**
     * Finalizes this hash state and returns the {@linkplain #hashLength() default hash length} bytes of hash output.
     */
    default byte @NotNull [] doFinalize() {
        byte[] hash = new byte[hashLength()];
        doFinalize(hash);
        return hash;
    }

    /**
     * Calculates the hash of the provided array slice in one pass.
     *
     * @param data   input data to calculate hash of
     * @param offset where in data to begin reading data to hash
     * @param length how many bytes of data to read
     * @return {@linkplain #hashLength() default hash length} byte array output
     */
    default byte @NotNull [] hash(byte @NotNull [] data, int offset, int length) {
        reset();
        update(data, offset, length);
        byte[] hash = new byte[hashLength()];
        doFinalize(hash);
        return hash;
    }

    /**
     * Calculates the hash of the provided array in one pass.
     *
     * @param data input data to calculate hash of
     * @return {@linkplain #hashLength() default hash length} byte array output
     */
    default byte @NotNull [] hash(byte @NotNull [] data) {
        return hash(data, 0, data.length);
    }
}
