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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class GimliTest {
    @Test
    void permute() {
        // test vector from gimli-20170627
        // adapted from:
        // https://github.com/ziglang/zig/blob/dd7b816d98840f26988c993eda9be21fa9b0ab50/lib/std/crypto/gimli.zig#L181-L208
        int[] start = new int[] {
                0x00000000, 0x9e3779ba, 0x3c6ef37a, 0xdaa66d46, 0x78dde724, 0x1715611a, 0xb54cdb2e, 0x53845566,
                0xf1bbcfc8, 0x8ff34a5a, 0x2e2ac522, 0xcc624026
        };
        int[] end = new int[] {
                0xba11c85a, 0x91bad119, 0x380ce880, 0xd24c2c68, 0x3eceffea, 0x277a921c, 0x4f73a0bd, 0xda5a9cd8,
                0x84b673f0, 0x34e52ff7, 0x9e2bef49, 0xf41bb8d6
        };
        Gimli gimli = new Gimli();
        gimli.init(start);
        gimli.permute();
        assertArrayEquals(end, gimli.extract());
    }
}
