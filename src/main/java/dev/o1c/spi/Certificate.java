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

public interface Certificate {
    /**
     * Identifies the certificate by a unique string such as its public key or some serialized subject info.
     *
     * @return identifier for this certificate or simply the public key if none is explicitly specified
     */
    byte @NotNull [] id();

    /**
     * Serializes the public key of this certificate to bytes.
     *
     * @return copy of public key data
     */
    byte @NotNull [] publicKey();

    /**
     * Returns the length of a key in bytes
     *
     * @return the length of a key in bytes
     */
    int keyLength();

    /**
     * Returns the length of a signature in bytes
     *
     * @return the length of a signature in bytes
     */
    int signatureLength();

    /**
     * Verifies that the given signature was produced on the given message with this certificate's private key. If the signature
     * does not match the message using this certificate, then {@link InvalidSignatureException} is thrown.
     *
     * @param message   original message that was signed
     * @param offset    where in the message buffer the signature input began
     * @param length    how many bytes in the message buffer were processed for the signature
     * @param signature signature data to verify
     * @param sigOffset where in the signature buffer the signature data begins
     */
    void verify(byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset);

    /**
     * Verifies that the given signature was produced on the given message with this certificate's private key. If the signature
     * does not match the message using this certificate, then {@link InvalidSignatureException} is thrown.
     *
     * @param message   original message that was signed
     * @param offset    where in the message buffer the signature input began
     * @param length    how many bytes in the message buffer were processed for the signature
     * @param signature signature data to verify
     */
    default void verify(byte @NotNull [] message, int offset, int length, byte @NotNull [] signature) {
        verify(message, offset, length, signature, 0);
    }

    /**
     * Verifies that the given signature was produced on the given message with this certificate's private key. If the signature
     * does not match the message using this certificate, then {@link InvalidSignatureException} is thrown.
     *
     * @param message   original message that was signed
     * @param signature signature data to verify
     */
    default void verify(byte @NotNull [] message, byte @NotNull [] signature) {
        verify(message, 0, message.length, signature, 0);
    }
}
