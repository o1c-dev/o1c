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

package dev.o1c.primitive;

import dev.o1c.spi.InvalidProviderException;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;
import java.util.ServiceLoader;

public interface EntropyChannel {
    void read(@NotNull ByteBuffer dst);

    default void read(byte @NotNull [] dst) {
        read(ByteBuffer.wrap(dst));
    }

    default void read(byte @NotNull [] dst, int off, int len) {
        read(ByteBuffer.wrap(dst, off, len));
    }

    static @NotNull EntropyChannel getInstance() {
        for (EntropyChannel entropyChannel : ServiceLoader.load(EntropyChannel.class)) {
            return entropyChannel;
        }
        throw new InvalidProviderException("No EntropyDaemon service providers found");
    }
}
