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

package dev.o1c.lwc;

import dev.o1c.spi.CipherKeyFactory;
import dev.o1c.spi.CipherKeyFactoryTest;
import dev.o1c.spi.Hash;
import dev.o1c.spi.CryptoHashTest;
import org.junit.jupiter.api.DynamicNode;

import java.util.List;

// https://csrc.nist.gov/projects/lightweight-cryptography/round-2-candidates
// test vectors can be regenerated from reference implementations
public class NistLwcTestVectors {
    public static List<DynamicNode> loadHashTestVectors(Hash hash) {
        String filename = String.format("LWC_HASH_KAT_%d.txt.gz", hash.hashLength() * Byte.SIZE);
        return CryptoHashTest.loadHashTests(filename, hash);
    }

    public static List<DynamicNode> loadAEADTestVectors(CipherKeyFactory factory) {
        String filename = String.format("LWC_AEAD_KAT_%d_128.txt.gz", factory.keyLength() * Byte.SIZE);
        return CipherKeyFactoryTest.loadAEADTests(filename, factory);
    }
}
