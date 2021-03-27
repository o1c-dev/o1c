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

public interface Hash {
    int hashLength();

    void reset();

    void update(byte b);

    default void update(byte @NotNull [] in) {
        update(in, 0, in.length);
    }

    void update(byte @NotNull [] in, int offset, int length);

    void finish(byte @NotNull [] out, int offset, int length);

    default void updateRLE(byte @NotNull [] buffer) {
        byte[] length = new byte[Integer.BYTES];
        ByteOps.packIntLE(buffer.length, length, 0);
        update(length);
        update(buffer);
    }

    default void finish(byte @NotNull [] out, int offset) {
        finish(out, offset, hashLength());
    }

    default void finish(byte @NotNull [] out) {
        finish(out, 0, out.length);
    }

    default byte @NotNull [] finish() {
        byte[] hash = new byte[hashLength()];
        finish(hash);
        return hash;
    }

    default byte @NotNull [] hash(byte @NotNull [] data, int offset, int length) {
        reset();
        update(data, offset, length);
        byte[] hash = new byte[hashLength()];
        finish(hash);
        return hash;
    }

    default byte @NotNull [] hash(byte @NotNull [] data) {
        return hash(data, 0, data.length);
    }
}
