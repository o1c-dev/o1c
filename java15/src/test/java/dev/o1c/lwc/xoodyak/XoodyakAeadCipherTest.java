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
import dev.o1c.lwc.NistLwcTestVectors;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class XoodyakAeadCipherTest {
    @Test
    void smokeTest() {
        byte[] pt = new byte[16];
        byte[] ct = new byte[32];
        byte[] key = new byte[16];
        byte[] nonce = new byte[16];
        AeadCipher cipher = new XoodyakAeadCipher();
        cipher.encrypt(new SecretKeySpec(key, cipher.algorithm()), nonce, new byte[0], pt, 0, pt.length, ct, 0, ct, pt.length);
        byte[] decrypted = new byte[16];
        cipher.decrypt(new SecretKeySpec(key, cipher.algorithm()), nonce, new byte[0], ct, 0, pt.length, ct, pt.length, decrypted, 0);
        assertArrayEquals(pt, decrypted);
    }

    @TestFactory
    List<DynamicNode> testVectors() throws IOException {
        return NistLwcTestVectors.loadAEADTestVectors(new XoodyakAeadCipher());
    }
}
