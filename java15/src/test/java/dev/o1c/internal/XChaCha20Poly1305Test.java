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
 */

package dev.o1c.internal;

import dev.o1c.util.ByteOps;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class XChaCha20Poly1305Test {
    @Test
    void subkeyDerivation() {
        var key = ByteOps.fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var nonce = ByteOps.fromHex("000000090000004a0000000031415927");
        var expectedKey = ByteOps.fromHex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
        var actualKey = XChaCha20Poly1305.calculateSubKey(key, nonce);
        assertArrayEquals(expectedKey, actualKey);
    }
}
