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

package dev.o1c.spi;

import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.DynamicNode;

import java.io.BufferedReader;
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

public class CipherKeyFactoryTest {
    public static @NotNull List<DynamicNode> loadAEADTests(@NotNull String testResource, @NotNull CipherKeyFactory keyFactory) {
        var vectors = new ArrayList<DynamicNode>(1088);
        var stream = keyFactory.getClass().getResourceAsStream(testResource);
        assertNotNull(stream, "No test resource found: " + testResource);
        try (var reader = new BufferedReader(new InputStreamReader(new GZIPInputStream(stream), StandardCharsets.UTF_8))) {
            var countLine = Pattern.compile("Count = (\\d+)");
            var keyLine = Pattern.compile("Key = ([0-9A-F]+)");
            var nonceLine = Pattern.compile("Nonce = ([0-9A-F]+)");
            var ptLine = Pattern.compile("PT = ([0-9A-F]*)");
            var adLine = Pattern.compile("AD = ([0-9A-F]*)");
            var ctLine = Pattern.compile("CT = ([0-9A-F]+)"); // concatenates ciphertext and tag
            for (int i = 0; i < 1088; i++) {
                var matcher = countLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                var count = matcher.group(1);
                matcher = keyLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                var key = keyFactory.parseKey(ByteOps.fromHex(matcher.group(1)));
                matcher = nonceLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                var nonce = ByteOps.fromHex(matcher.group(1));
                matcher = ptLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                var pt = matcher.group(1);
                var plaintext = ByteOps.fromHex(pt);
                matcher = adLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                var ad = matcher.group(1);
                var context = ByteOps.fromHex(ad);
                matcher = ctLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                var ct = matcher.group(1);
                var ciphertext = ByteOps.fromHex(ct);
                reader.readLine(); // empty line
                vectors.add(dynamicContainer("P[" + pt + "]A[" + ad + "]", List.of(
                        dynamicTest("encrypt", () -> {
                            var encrypted = new byte[ciphertext.length];
                            key.encrypt(nonce, context, plaintext, 0, plaintext.length, encrypted, 0, encrypted,
                                    plaintext.length);
                            assertArrayEquals(ciphertext, encrypted);
                        }),
                        dynamicTest("decrypt", () -> {
                            var decrypted = new byte[plaintext.length];
                            key.decrypt(nonce, context, ciphertext, 0, plaintext.length, ciphertext, plaintext.length,
                                    decrypted, 0);
                            assertArrayEquals(plaintext, decrypted);
                        })
                )));
            }
        } catch (IOException e) {
            fail(e);
        }
        return vectors;
    }
}
