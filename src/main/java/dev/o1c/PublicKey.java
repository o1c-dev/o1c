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

package dev.o1c;

import org.jetbrains.annotations.NotNull;

/**
 * Contains the public part of a {@link KeyPair}.
 */
public interface PublicKey {

    /**
     * Opens a signed message and returns its plaintext contents if its signature can be verified with this public key.
     *
     * @param signedMessage signed message data containing both plaintext and signature
     * @return plaintext data if signature matches
     * @throws dev.o1c.spi.InvalidSignatureException if the signature does not match or is otherwise invalid
     */
    byte @NotNull [] openSignedMessage(byte @NotNull [] signedMessage);

    /**
     * Validates the signature of a sealed box created by the given sender to this public key recipient in the given
     * context.
     *
     * @param sender    who created the sealed box
     * @param sealedBox sealed box data to validate signature
     * @param context   original context the sealed box was created in
     * @throws dev.o1c.spi.InvalidSignatureException if the seal is broken (an invalid signature)
     */
    void validateSealedBox(@NotNull PublicKey sender, byte @NotNull [] sealedBox, byte @NotNull [] context);

}
