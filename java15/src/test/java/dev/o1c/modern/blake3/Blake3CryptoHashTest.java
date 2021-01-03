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

package dev.o1c.modern.blake3;

import com.fasterxml.jackson.jr.ob.JSON;
import dev.o1c.util.ByteOps;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class Blake3CryptoHashTest {
    @TestFactory
    List<DynamicNode> testVectors() throws IOException {
        var json = JSON.builder().enable(JSON.Feature.USE_FIELDS).build();
        var testVector = json.beanFrom(TestVector.class, getClass().getResourceAsStream("test_vectors.json"));
        var key = testVector.key.getBytes(StandardCharsets.UTF_8);
        var context = testVector.context_string.getBytes(StandardCharsets.UTF_8);
        var tests = new ArrayList<DynamicNode>();
        var hasher = Blake3CryptoHash.init();
        for (Case testCase : testVector.cases) {
            var input = new byte[testCase.input_len];
            for (int i = 0; i < input.length; i++) {
                input[i] = (byte) (i % 251);
            }
            var hash = ByteOps.fromHex(testCase.hash);
            var truncatedHash = Arrays.copyOf(hash, 32);
            var keyedHash = ByteOps.fromHex(testCase.keyed_hash);
            var truncatedKeyedHash = Arrays.copyOf(keyedHash, 32);
            var deriveKey = ByteOps.fromHex(testCase.derive_key);
            var truncatedDeriveKey = Arrays.copyOf(deriveKey, 32);
            tests.add(dynamicContainer("input length=" + testCase.input_len, List.of(
                    dynamicTest("hash xof", () -> {
                        hasher.reset();
                        hasher.update(input);
                        var actual = new byte[hash.length];
                        hasher.finish(actual);
                        assertArrayEquals(hash, actual);
                    }),
                    dynamicTest("hash 256",
                            () -> assertArrayEquals(truncatedHash, hasher.hash(input))),
                    dynamicTest("keyed hash xof", () -> {
                        var blake3 = Blake3CryptoHash.init(key);
                        blake3.update(input);
                        var actual = new byte[keyedHash.length];
                        blake3.finish(actual);
                        assertArrayEquals(keyedHash, actual);
                    }),
                    dynamicTest("keyed hash 256",
                            () -> assertArrayEquals(truncatedKeyedHash, Blake3CryptoHash.init(key).hash(input))),
                    dynamicTest("derive key xof", () -> {
                        var blake3 = Blake3CryptoHash.initKDF(context);
                        blake3.update(input);
                        var actual = new byte[deriveKey.length];
                        blake3.finish(actual);
                        assertArrayEquals(deriveKey, actual);
                    }),
                    dynamicTest("derive key 256",
                            () -> assertArrayEquals(truncatedDeriveKey, Blake3CryptoHash.initKDF(context).hash(input)))
            )));
        }
        return tests;
    }

    static class TestVector {
        public String key;
        public String context_string;
        public Case[] cases;
    }

    static class Case {
        public int input_len;
        public String hash;
        public String keyed_hash;
        public String derive_key;
    }
}
