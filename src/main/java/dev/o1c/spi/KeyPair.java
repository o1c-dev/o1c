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

public interface KeyPair extends PublicKey {
    void sign(byte @NotNull [] message, int offset, int length, byte @NotNull [] signature, int sigOffset);

    default byte @NotNull [] sign(byte @NotNull [] message, int offset, int length) {
        byte[] signature = new byte[signatureLength()];
        sign(message, offset, length, signature, 0);
        return signature;
    }

    default byte @NotNull [] sign(byte @NotNull [] message) {
        return sign(message, 0, message.length);
    }

    void exchangeSecret(@NotNull PublicKey peer, byte @NotNull [] secret, int offset);

    default byte @NotNull [] exchangeSecret(@NotNull PublicKey peer) {
        byte[] secret = new byte[keyLength()];
        exchangeSecret(peer, secret, 0);
        return secret;
    }

    void encrypt(
            @NotNull PublicKey recipient, byte @NotNull [] nonce, byte @NotNull [] context,
            byte @NotNull [] plaintext, int ptOffset, int ptLength,
            byte @NotNull [] ciphertext, int ctOffset, byte @NotNull [] tag, int tagOffset);

    void decrypt(
            @NotNull PublicKey sender, byte @NotNull [] nonce, byte @NotNull [] context,
            byte @NotNull [] ciphertext, int ctOffset, int ctLength, byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] plaintext, int ptOffset);

    void signcrypt(
            @NotNull PublicKey recipient, byte @NotNull [] nonce, byte @NotNull [] context,
            byte @NotNull [] plaintext, int ptOffset, int ptLength,
            byte @NotNull [] ciphertext, int ctOffset,
            byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] signature, int sigOffset);

    void unsigncrypt(
            @NotNull PublicKey sender, byte @NotNull [] nonce, byte @NotNull [] context,
            byte @NotNull [] ciphertext, int ctOffset, int ctLength,
            byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] signature, int sigOffset,
            byte @NotNull [] plaintext, int ptOffset);
}