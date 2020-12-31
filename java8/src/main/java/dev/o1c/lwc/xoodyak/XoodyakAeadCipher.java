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

package dev.o1c.lwc.xoodyak;

import dev.o1c.primitive.AeadCipher;
import dev.o1c.spi.InvalidAuthenticationTagException;
import org.bouncycastle.util.Arrays;
import org.jetbrains.annotations.NotNull;

import javax.crypto.SecretKey;
import java.security.MessageDigest;

public class XoodyakAeadCipher implements AeadCipher {
    private static final int KEY_SIZE = 16;
    private static final int NONCE_SIZE = 16;
    private static final int TAG_SIZE = 16;
    private static final String ALGORITHM = "Xoodyak";

    /*
    AEAD with shared secret (DH)
Cyclist(ε, ε, ε)
Absorb(ID of the chosen protocol)
Absorb(KA) {Alice’s public key}
Absorb(KB) {Bob’s public key}
Absorb(KAB) {Their common secret produced with Diffie-Hellman}
KD ← Squeeze(l)

Cyclist(KD , ε, ε)
Absorb(nonce)
Absorb(A)
C ← Encrypt(P)
T ← Squeeze(t)
return (C, T )
     */

    private final Xoodyak xoodyak = new Xoodyak();

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

    @Override
    public void encrypt(
            @NotNull SecretKey key, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset,
            int length, byte @NotNull [] out, int outOffset, byte @NotNull [] tag, int tagOffset) {
        byte[] keyData = key.getEncoded();
        checkKeySize(keyData.length);
        checkNonceSize(nonce.length);
        xoodyak.initialize(keyData);
        xoodyak.absorb(nonce, 0, NONCE_SIZE);
        xoodyak.absorb(context, 0, context.length);
        xoodyak.encrypt(in, offset, length, out, outOffset);
        xoodyak.squeeze(tag, tagOffset, TAG_SIZE);
//        xoodyak.ratchet();
    }

    @Override
    public void decrypt(
            @NotNull SecretKey key, byte @NotNull [] nonce, byte @NotNull [] context, byte @NotNull [] in, int offset,
            int length, byte @NotNull [] tag, int tagOffset, byte @NotNull [] out, int outOffset) {
        byte[] keyData = key.getEncoded();
        checkKeySize(keyData.length);
        checkNonceSize(nonce.length);
        xoodyak.initialize(keyData);
        xoodyak.absorb(nonce, 0, NONCE_SIZE);
        xoodyak.absorb(context, 0, context.length);
        xoodyak.decrypt(in, offset, length, out, outOffset);
        byte[] actual = new byte[TAG_SIZE];
        xoodyak.squeeze(actual, 0, TAG_SIZE);
//        xoodyak.ratchet();
        byte[] expected = Arrays.copyOfRange(tag, tagOffset, tagOffset + TAG_SIZE);
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new InvalidAuthenticationTagException("Tag mismatch");
        }
    }

}
