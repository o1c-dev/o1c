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

package dev.o1c.lwc.gimli;

import dev.o1c.spi.CipherKey;
import dev.o1c.spi.InvalidAuthenticationTagException;
import org.jetbrains.annotations.NotNull;

import java.security.MessageDigest;
import java.util.Arrays;

// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/gimli-spec-round2.pdf
// https://keccak.team/sponge_duplex.html
// https://github.com/ziglang/zig/blob/master/lib/std/crypto/gimli.zig
// primitive = aead/gimli24v1 with hash/gimli24v1
class GimliCipherKey implements CipherKey {
    private final Gimli gimli = new Gimli();
    private final byte[] key;

    GimliCipherKey(byte @NotNull [] key) {
        this.key = key;
    }

    @Override
    public int nonceSize() {
        return 16;
    }

    @Override
    public int tagSize() {
        return 16;
    }

    @Override
    public void encrypt(
            byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length, byte @NotNull [] out,
            int outOffset, byte @NotNull [] tag, int tagOffset) {
        checkNonceSize(nonce.length);
        gimli.init(key, nonce);
        gimli.absorb(context);
        gimli.encrypt(in, offset, length, out, outOffset);
        gimli.squeeze(tag, tagOffset, tagSize());
        gimli.reset(); // or ratchet
    }

    @Override
    public void decrypt(
            byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset, int length, byte @NotNull [] tag,
            int tagOffset, byte @NotNull [] out, int outOffset) {
        checkNonceSize(nonce.length);
        gimli.init(key, nonce);
        gimli.absorb(context);
        gimli.decrypt(in, offset, length, out, outOffset);
        byte[] expected = Arrays.copyOfRange(tag, tagOffset, tagOffset + tagSize());
        byte[] actual = new byte[tagSize()];
        gimli.squeeze(actual);
        gimli.reset(); // or ratchet
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new InvalidAuthenticationTagException("Tag mismatch");
        }
    }
}
