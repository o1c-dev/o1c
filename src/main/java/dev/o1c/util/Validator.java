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

package dev.o1c.util;

import org.jetbrains.annotations.NotNull;

public final class Validator {
    private Validator() {
    }

    public static void checkBufferArgs(byte @NotNull [] buffer, int offset, int length) {
        if (offset < 0) {
            throw new IndexOutOfBoundsException("Offset must be non-negative but got " + offset);
        }
        if (length < 0) {
            throw new IndexOutOfBoundsException("Length must be non-negative but got " + length);
        }
        if (offset > buffer.length - length) {
            throw new IndexOutOfBoundsException(
                    "Offset " + offset + " and length " + length + " does not fit in provided array");
        }
    }
}
