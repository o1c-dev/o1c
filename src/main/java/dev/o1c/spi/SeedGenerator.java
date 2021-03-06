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

import org.jetbrains.annotations.ApiStatus;
import org.jetbrains.annotations.NotNull;

import java.util.ServiceLoader;

/**
 * Generates seed data for {@link RandomBytesGenerator} implementations using system entropy sources.
 */
@ApiStatus.Internal
public interface SeedGenerator {

    /**
     * Generates the requested number of bytes of entropy.
     *
     * @param nrBytes how many bytes of entropy to gather
     * @return a new cryptographic seed
     */
    byte @NotNull [] generateSeed(int nrBytes);

    /**
     * Gets the default SeedGenerator.
     *
     * @return the default SeedGenerator
     */
    static @NotNull SeedGenerator getInstance() {
        for (SeedGenerator generator : ServiceLoader.load(SeedGenerator.class)) {
            return generator;
        }
        throw new InvalidProviderException("No SeedGenerator providers found");
    }
}
