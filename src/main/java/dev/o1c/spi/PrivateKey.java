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

public interface PrivateKey extends Certificate {
    /**
     * Signs the given message and writes the signature to the given signature array.
     *
     * @param message   buffer to read data to sign
     * @param offset    where in the buffer to begin reading data to sign
     * @param length    how many bytes in the buffer to read for signing
     * @param signature buffer to write signature to
     * @param sigOffset where in the buffer to begin writing the signature
     */
    void sign(byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset);

    /**
     * Returns the signature of the given message.
     *
     * @param message buffer to read data to sign
     * @param offset  where in the buffer to begin reading data to sign
     * @param length  how many bytes in the buffer to read for signing
     * @return signature of the given message
     */
    default byte @NotNull [] sign(byte @NotNull [] message, int offset, int length) {
        byte[] sig = new byte[signatureLength()];
        sign(message, offset, length, sig, 0);
        return sig;
    }

    /**
     * Returns the signature of the given message.
     *
     * @param message message to sign
     * @return signature of the given message
     */
    default byte @NotNull [] sign(byte @NotNull [] message) {
        return sign(message, 0, message.length);
    }

    /**
     * Calculates the shared secret between this key and the given peer.
     *
     * @param peer other side to calculate secret between
     * @return shared secret value for further key derivation use
     */
    byte @NotNull [] sharedSecret(@NotNull Certificate peer);
}
