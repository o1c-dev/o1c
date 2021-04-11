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
import org.jetbrains.annotations.Nullable;

public interface KeyFactory {
    default @NotNull KeyPair generateKey() {
        return generateKey(null);
    }

    @NotNull KeyPair generateKey(byte @Nullable [] id);

    default @NotNull KeyPair parsePrivateKey(byte @NotNull [] keyData) {
        return parsePrivateKey(null, keyData);
    }

    @NotNull KeyPair parsePrivateKey(byte @Nullable [] id, byte @NotNull [] keyData);

    default @NotNull PublicKey parsePublicKey(byte @NotNull [] keyData) {
        return parsePublicKey(null, keyData);
    }

    @NotNull PublicKey parsePublicKey(byte @Nullable [] id, byte @NotNull [] keyData);
}
