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

import dev.o1c.spi.Cipher;
import dev.o1c.spi.InvalidAuthenticationTagException;
import dev.o1c.util.Validator;
import org.jetbrains.annotations.NotNull;

import java.security.MessageDigest;
import java.util.Arrays;

// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/gimli-spec-round2.pdf
// https://keccak.team/sponge_duplex.html
// https://github.com/ziglang/zig/blob/master/lib/std/crypto/gimli.zig
// primitive = aead/gimli24v1 with hash/gimli24v1
class GimliCipher implements Cipher {
    private final Gimli gimli = new Gimli();
    private long counter;

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public int nonceLength() {
        return 16;
    }

    @Override
    public void init(byte @NotNull [] key, byte @NotNull [] nonce, byte @NotNull [] context) {
        checkKeyLength(key.length);
        checkNonceLength(nonce.length);
        gimli.setKey(key);
        gimli.setNonce(nonce);
        gimli.permute();
        gimli.absorb(context);
        counter = 0;
    }

    @Override
    public int tagLength() {
        return 16;
    }

    @Override
    public void encrypt(
            byte @NotNull [] plaintext, int ptOffset, int ptLength, byte @NotNull [] ciphertext, int ctOffset,
            byte @NotNull [] tag, int tagOffset) {
        Validator.checkBufferArgs(plaintext, ptOffset, ptLength);
        Validator.checkBufferArgs(ciphertext, ctOffset, ptLength);
        Validator.checkBufferArgs(tag, tagOffset, tagLength());
        gimli.encrypt(plaintext, ptOffset, ptLength, ciphertext, ctOffset);
        gimli.squeeze(tag, tagOffset, tagLength());
        gimli.ratchet(counter);
        if (++counter == 0) {
            gimli.reset();
        }
    }

    @Override
    public void decrypt(
            byte @NotNull [] ciphertext, int ctOffset, int ctLength, byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] plaintext, int ptOffset) {
        Validator.checkBufferArgs(ciphertext, ctOffset, ctLength);
        Validator.checkBufferArgs(tag, tagOffset, tagLength());
        Validator.checkBufferArgs(plaintext, ptOffset, ctLength);
        gimli.decrypt(ciphertext, ctOffset, ctLength, plaintext, ptOffset);
        byte[] expected = Arrays.copyOfRange(tag, tagOffset, tagOffset + tagLength());
        byte[] actual = new byte[tagLength()];
        gimli.squeeze(actual);
        gimli.ratchet(counter);
        if (++counter == 0) {
            gimli.reset();
        }
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new InvalidAuthenticationTagException("Tag mismatch");
        }
    }
}
