/*
 * ISC License
 *
 * Copyright (c) 2020, Matt Sicker
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

package dev.o1c.lwc.gimli;

import dev.o1c.primitive.AeadCipher;
import dev.o1c.spi.InvalidAuthenticationTagException;
import org.jetbrains.annotations.NotNull;

import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.util.Arrays;

// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/gimli-spec-round2.pdf
// https://keccak.team/sponge_duplex.html
// https://github.com/ziglang/zig/blob/master/lib/std/crypto/gimli.zig
// primitive = aead/gimli24v1 with hash/gimli24v1
public final class GimliAeadCipher implements AeadCipher {
    private static final int KEY_SIZE = 32;
    private static final int NONCE_SIZE = 16;
    private static final int TAG_SIZE = 16;
    private static final String ALGORITHM = "Gimli24v1";

    private final Gimli gimli = new Gimli();

    @Override
    public int keySize() {
        return KEY_SIZE;
    }

    @Override
    public int nonceSize() {
        return NONCE_SIZE;
    }

    @Override
    public int tagSize() {
        return TAG_SIZE;
    }

    @Override
    public @NotNull String algorithm() {
        return ALGORITHM;
    }

    private void init(SecretKey key, byte[] nonce, byte[] context) {
        byte[] keyData = key.getEncoded();
        checkKeySize(keyData.length);
        checkNonceSize(nonce.length);
        gimli.init(keyData, nonce);
        gimli.absorb(context);
    }

    @Override
    public void encrypt(
            @NotNull SecretKey key, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset,
            int length, byte @NotNull [] out, int outOffset, byte @NotNull [] tag, int tagOffset) {
        init(key, nonce, context);
        gimli.encrypt(in, offset, length, out, outOffset);
        gimli.squeeze(tag, tagOffset, TAG_SIZE);
        gimli.reset();
    }

    @Override
    public void decrypt(
            @NotNull SecretKey key, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset,
            int length, byte @NotNull [] tag, int tagOffset, byte @NotNull [] out, int outOffset) {
        init(key, nonce, context);
        gimli.decrypt(in, offset, length, out, outOffset);
        byte[] expected = Arrays.copyOfRange(tag, tagOffset, tagOffset + TAG_SIZE);
        byte[] actual = new byte[TAG_SIZE];
        gimli.squeeze(actual);
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new InvalidAuthenticationTagException("Tag mismatch");
        }
    }
}
