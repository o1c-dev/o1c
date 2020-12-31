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

package dev.o1c.lwc;

import dev.o1c.primitive.CipherKeyFactory;
import dev.o1c.primitive.CryptoHash;
import dev.o1c.util.ByteOps;
import org.junit.jupiter.api.DynamicNode;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

// https://csrc.nist.gov/projects/lightweight-cryptography/round-2-candidates
// test vectors can be regenerated from reference implementations
public class NistLwcTestVectors {
    public static List<DynamicNode> loadHashTestVectors(CryptoHash hash) throws IOException {
        var testVectors = 1024;
        var vectors = new ArrayList<DynamicNode>(testVectors);
        try (var reader = loadResource(hash.getClass(),
                String.format("LWC_HASH_KAT_%d.txt.gz", hash.getDefaultHashSize() * Byte.SIZE))) {
            var countLine = Pattern.compile("Count = (\\d+)");
            var msgLine = Pattern.compile("Msg = ([0-9A-F]*)");
            var hashLine = Pattern.compile("MD = ([0-9A-F]{64})");
            for (int i = 0; i < testVectors; i++) {
                var countMatcher = countLine.matcher(reader.readLine());
                assertTrue(countMatcher.matches());
                var count = countMatcher.group(1);
                var msgMatcher = msgLine.matcher(reader.readLine());
                assertTrue(msgMatcher.matches());
                var msg = msgMatcher.group(1);
                var hashMatcher = hashLine.matcher(reader.readLine());
                assertTrue(hashMatcher.matches());
                var md = hashMatcher.group(1);
                reader.readLine(); // empty line
                vectors.add(generateHashTests(hash, count, msg, md));
            }
        }
        return vectors;
    }

    public static List<DynamicNode> loadAEADTestVectors(CipherKeyFactory factory) throws IOException {
        var testVectors = 1088;
        var vectors = new ArrayList<DynamicNode>(testVectors);
        var filename = String.format("LWC_AEAD_KAT_%d_128.txt.gz", factory.keySize() * Byte.SIZE);
        try (var reader = loadResource(factory.getClass(), filename)) {
            var countLine = Pattern.compile("Count = (\\d+)");
            var keyLine = Pattern.compile("Key = ([0-9A-F]+)");
            var nonceLine = Pattern.compile("Nonce = ([0-9A-F]+)");
            var ptLine = Pattern.compile("PT = ([0-9A-F]*)");
            var adLine = Pattern.compile("AD = ([0-9A-F]*)");
            var ctLine = Pattern.compile("CT = ([0-9A-F]+)"); // concatenates ciphertext and tag
            for (int i = 0; i < testVectors; i++) {
                var countMatcher = countLine.matcher(reader.readLine());
                assertTrue(countMatcher.matches());
                var count = countMatcher.group(1);
                var keyMatcher = keyLine.matcher(reader.readLine());
                assertTrue(keyMatcher.matches());
                var key = keyMatcher.group(1);
                var nonceMatcher = nonceLine.matcher(reader.readLine());
                assertTrue(nonceMatcher.matches());
                var nonce = nonceMatcher.group(1);
                var ptMatcher = ptLine.matcher(reader.readLine());
                assertTrue(ptMatcher.matches());
                var pt = ptMatcher.group(1);
                var adMatcher = adLine.matcher(reader.readLine());
                assertTrue(adMatcher.matches());
                var ad = adMatcher.group(1);
                var ctMatcher = ctLine.matcher(reader.readLine());
                assertTrue(ctMatcher.matches());
                var ct = ctMatcher.group(1);
                reader.readLine(); // empty line
                vectors.add(generateAEADTests(factory, count, key, nonce, pt, ad, ct));
            }
        }
        return vectors;
    }

    private static BufferedReader loadResource(Class<?> clazz, String filename) throws IOException {
        var stream = clazz.getResourceAsStream(filename);
        if (stream == null) {
            throw new FileNotFoundException(filename);
        }
        return new BufferedReader(new InputStreamReader(new GZIPInputStream(stream), StandardCharsets.UTF_8));
    }

    private static DynamicNode generateHashTests(CryptoHash hash, String count, String msg, String md) {
        var message = ByteOps.fromHex(msg);
        var expected = ByteOps.fromHex(md);
        return dynamicContainer("hash#" + count + "<" + msg + ">", List.of(
                dynamicTest("hash byte[]", () -> assertArrayEquals(expected, hash.hash(message))),
                dynamicTest("reset/update/finish byte[]", () -> {
                    hash.reset();
                    hash.update(message);
                    assertArrayEquals(expected, hash.finish());
                })
        ));
        // TODO: test out hashing per-byte and other partial hashing
    }

    private static DynamicNode generateAEADTests(
            CipherKeyFactory factory, String count, String keyInput, String nonceInput, String plaintextInput, String contextInput,
            String ciphertextInput) {
        var key = factory.parseKey(ByteOps.fromHex(keyInput));
        var nonce = ByteOps.fromHex(nonceInput);
        var plaintext = ByteOps.fromHex(plaintextInput);
        var context = ByteOps.fromHex(contextInput);
        var ciphertext = ByteOps.fromHex(ciphertextInput);
        return dynamicContainer("aead#" + count + "<" + plaintextInput + "," + contextInput + ">", List.of(
                dynamicTest("encrypt", () -> {
                    var actual = new byte[ciphertext.length];
                    key.encrypt(nonce, context, plaintext, 0, plaintext.length, actual, 0, actual, plaintext.length);
                    assertArrayEquals(ciphertext, actual);
                }),
                dynamicTest("decrypt byte[]", () -> {
                    var actual = new byte[plaintext.length];
                    assertDoesNotThrow(() -> key.decrypt(nonce, context, ciphertext, 0, plaintext.length, ciphertext, plaintext.length, actual, 0));
                    assertArrayEquals(plaintext, actual);
                })
        ));
    }
}
