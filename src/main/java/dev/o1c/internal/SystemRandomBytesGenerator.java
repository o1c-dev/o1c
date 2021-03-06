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

package dev.o1c.internal;

import dev.o1c.spi.InvalidProviderException;
import dev.o1c.spi.RandomBytesGenerator;
import dev.o1c.util.Validator;
import org.jetbrains.annotations.NotNull;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SystemRandomBytesGenerator implements RandomBytesGenerator {
    private static final ThreadLocal<SystemRandomBytesGenerator> CURRENT = new ThreadLocal<>();

    private final SecureRandom random;

    public SystemRandomBytesGenerator() {
        try {
            random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidProviderException(e);
        }
    }

    @Override
    public void generateBytes(byte @NotNull [] out) {
        random.nextBytes(out);
    }

    @Override
    public void generateBytes(byte @NotNull [] out, int offset, int length) {
        Validator.checkBufferArgs(out, offset, length);
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        System.arraycopy(bytes, 0, out, offset, length);
    }

    public static @NotNull SystemRandomBytesGenerator getInstance() {
        if (CURRENT.get() == null) {
            CURRENT.set(new SystemRandomBytesGenerator());
        }
        return CURRENT.get();
    }
}
