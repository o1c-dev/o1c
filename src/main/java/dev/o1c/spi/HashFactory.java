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

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

import java.nio.charset.StandardCharsets;

/**
 * Creates cryptographic hash instance variants for various use cases.
 */
public interface HashFactory {

    /**
     * Creates a new plain Hash instance with an algorithm-specific default hash output length.
     */
    @NotNull Hash newHash();

    /**
     * Creates a new plain Hash instance with the provided default hash output length.
     */
    @NotNull Hash newHash(@Range(from = 0, to = Integer.MAX_VALUE) int hashLength);

    /**
     * Creates a new keyed Hash instance using the provided secret key.
     */
    @NotNull Hash newKeyedHash(byte @NotNull [] key);

    /**
     * Creates a new key derivation function (KDF) Hash instance for the provided key derivation context.
     */
    @NotNull Hash newKeyDerivationFunction(byte @NotNull [] context);

    /**
     * Creates a new key derivation function (KDF) Hash instance for the provided key derivation context.
     */
    default @NotNull Hash newKeyDerivationFunction(@NotNull String context) {
        return newKeyDerivationFunction(context.getBytes(StandardCharsets.UTF_8));
    }
}
