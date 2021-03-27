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

package dev.o1c.impl.blake3;

import com.fasterxml.jackson.jr.ob.JSON;
import dev.o1c.spi.Hash;
import dev.o1c.spi.HashFactory;
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

class Blake3HashTest {
    @TestFactory
    List<DynamicNode> testVectors() throws IOException {
        JSON json = JSON.builder().enable(JSON.Feature.USE_FIELDS).build();
        TestVector testVector = json.beanFrom(TestVector.class, getClass().getResourceAsStream("test_vectors.json"));
        byte[] key = testVector.key.getBytes(StandardCharsets.UTF_8);
        byte[] context = testVector.context_string.getBytes(StandardCharsets.UTF_8);
        List<DynamicNode> tests = new ArrayList<>();
        HashFactory hashFactory = Blake3HashFactory.INSTANCE;
        Hash hasher = hashFactory.newHash();
        for (Case testCase : testVector.cases) {
            byte[] input = new byte[testCase.input_len];
            for (int i = 0; i < input.length; i++) {
                input[i] = (byte) (i % 251);
            }
            byte[] hash = ByteOps.fromHex(testCase.hash);
            byte[] truncatedHash = Arrays.copyOf(hash, 32);
            byte[] keyedHash = ByteOps.fromHex(testCase.keyed_hash);
            byte[] truncatedKeyedHash = Arrays.copyOf(keyedHash, 32);
            byte[] deriveKey = ByteOps.fromHex(testCase.derive_key);
            byte[] truncatedDeriveKey = Arrays.copyOf(deriveKey, 32);
            tests.add(dynamicContainer("input length=" + testCase.input_len, Arrays.asList(
                    dynamicTest("hash xof", () -> {
                        hasher.reset();
                        hasher.update(input);
                        byte[] actual = new byte[hash.length];
                        hasher.doFinalize(actual);
                        assertArrayEquals(hash, actual);
                    }),
                    dynamicTest("hash 256",
                            () -> assertArrayEquals(truncatedHash, hasher.hash(input))),
                    dynamicTest("keyed hash xof", () -> {
                        Hash blake3 = hashFactory.newKeyedHash(key);
                        blake3.update(input);
                        byte[] actual = new byte[keyedHash.length];
                        blake3.doFinalize(actual);
                        assertArrayEquals(keyedHash, actual);
                    }),
                    dynamicTest("keyed hash 256",
                            () -> assertArrayEquals(truncatedKeyedHash, hashFactory.newKeyedHash(key).hash(input))),
                    dynamicTest("derive key xof", () -> {
                        Hash blake3 = hashFactory.newKeyDerivationFunction(context);
                        blake3.update(input);
                        byte[] actual = new byte[deriveKey.length];
                        blake3.doFinalize(actual);
                        assertArrayEquals(deriveKey, actual);
                    }),
                    dynamicTest("derive key 256",
                            () -> assertArrayEquals(truncatedDeriveKey, hashFactory.newKeyDerivationFunction(context).hash(input)))
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
