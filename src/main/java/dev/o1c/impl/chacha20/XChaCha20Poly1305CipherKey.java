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

package dev.o1c.impl.chacha20;

import dev.o1c.spi.CipherKey;
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;

/**
 * Implements the extended-nonce cipher XChaCha20-Poly1305.
 */
// https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03
public class XChaCha20Poly1305CipherKey implements CipherKey {
    private final ChaCha20 hChaCha = new ChaCha20();

    XChaCha20Poly1305CipherKey(byte @NotNull [] key) {
        hChaCha.initKey(key);
    }

    @Override
    public int nonceLength() {
        return 24;
    }

    @Override
    public int tagLength() {
        return 16;
    }

    @Override
    public void encrypt(
            byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length, byte @NotNull [] out,
            int outOffset, byte @NotNull [] tag, int tagOffset) {
        checkNonceLength(nonce.length);
        byte[] hNonce = Arrays.copyOf(nonce, 16);
        byte[] sNonce = Arrays.copyOfRange(nonce, 12, 24);
        ByteOps.overwriteWithZeroes(sNonce, 0, 4);
        ChaCha20Poly1305CipherKey subKey = new ChaCha20Poly1305CipherKey(hChaCha.hKey(hNonce));
        subKey.encrypt(sNonce, context, in, offset, length, out, outOffset, tag, tagOffset);
    }

    @Override
    public void decrypt(
            byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length, byte @NotNull [] tag,
            int tagOffset, byte @NotNull [] out, int outOffset) {
        checkNonceLength(nonce.length);
        byte[] hNonce = Arrays.copyOf(nonce, 16);
        byte[] sNonce = Arrays.copyOfRange(nonce, 12, 24);
        ByteOps.overwriteWithZeroes(sNonce, 0, 4);
        ChaCha20Poly1305CipherKey subKey = new ChaCha20Poly1305CipherKey(hChaCha.hKey(hNonce));
        subKey.decrypt(sNonce, context, in, offset, length, tag, tagOffset, out, outOffset);
    }
}
