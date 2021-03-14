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
import dev.o1c.spi.InvalidAuthenticationTagException;
import org.jetbrains.annotations.NotNull;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Implements RFC 8439 version of ChaCha20-Poly1305.
 *
 * @see <a href="https://tools.ietf.org/html/rfc8439">RFC 8439</a>
 */
public class ChaCha20Poly1305CipherKey implements CipherKey {
    private final ChaCha20 cipher = new ChaCha20();
    private final Poly1305 authenticator = new Poly1305();

    ChaCha20Poly1305CipherKey(byte[] key) {
        cipher.initKey(key);
    }

    @Override
    public int nonceLength() {
        return 12;
    }

    @Override
    public int tagLength() {
        return 16;
    }

    @Override
    public void encrypt(
            byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length,
            byte @NotNull [] out, int outOffset, byte @NotNull [] tag, int tagOffset) {
        checkNonceLength(nonce.length);
        init(nonce, context);
        cipher.crypt(in, offset, length, out, outOffset);
        authenticator.updatePad(out, outOffset, length);
        authenticator.updateLengths(context.length, length);
        authenticator.computeMac(tag, tagOffset);
    }

    @Override
    public void decrypt(
            byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length,
            byte @NotNull [] tag, int tagOffset, byte @NotNull [] out, int outOffset) {
        checkNonceLength(nonce.length);
        init(nonce, context);
        authenticator.updatePad(in, offset, length);
        authenticator.updateLengths(context.length, length);
        byte[] actualTag = authenticator.computeMac();
        byte[] expectedTag = Arrays.copyOfRange(tag, tagOffset, tagOffset + tagLength());
        if (!MessageDigest.isEqual(expectedTag, actualTag)) {
            throw new InvalidAuthenticationTagException("Tag mismatch");
        }
        cipher.crypt(in, offset, length, out, outOffset);
    }

    private void init(byte[] nonce, byte[] context) {
        cipher.initNonce(nonce);
        cipher.initCounter(0);
        authenticator.init(cipher.polyKey());
        authenticator.updatePad(context, 0, context.length);
    }
}
