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

public interface PublicKey {
    /**
     * Identifies this public key with a unique byte string such as the public key itself or some other principal identifier.
     *
     * @return identifier of this key
     */
    byte @NotNull [] id();

    /**
     * Returns the length of this key in bytes.
     *
     * @return the length of this key in bytes
     */
    int keyLength();

    /**
     * Returns the length of signatures this key uses.
     *
     * @return the length of signatures in bytes
     */
    int signatureLength();

    /**
     * Checks if the given message and signature were signed by this key's private key.
     *
     * @param signature message signature to validate
     * @param message   message buffer to validate
     * @param offset    where in the message buffer to validate from
     * @param length    how many bytes in the message buffer to validate
     * @return true if the signature is valid for this key or false otherwise
     */
    boolean isValidSignature(byte @NotNull [] signature, byte @NotNull [] message, int offset, int length);

    /**
     * Checks if the given message and signature were signed by this key's private key.
     *
     * @param signature message signature to validate
     * @param message   message buffer to validate
     * @return true if the signature is valid for this key or false otherwise
     */
    default boolean isValidSignature(byte @NotNull [] signature, byte @NotNull [] message) {
        return isValidSignature(signature, message, 0, message.length);
    }
}
