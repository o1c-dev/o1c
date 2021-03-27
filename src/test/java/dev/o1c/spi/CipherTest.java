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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

public class CipherTest {
    public static @NotNull List<DynamicNode> loadAEADTests(@NotNull String testResource, @NotNull Cipher cipher) {
        List<DynamicNode> vectors = new ArrayList<>(1088);
        InputStream stream = cipher.getClass().getResourceAsStream(testResource);
        assertNotNull(stream, "No test resource found: " + testResource);
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new GZIPInputStream(stream), StandardCharsets.UTF_8))) {
            Pattern countLine = Pattern.compile("Count = (\\d+)");
            Pattern keyLine = Pattern.compile("Key = ([0-9A-F]+)");
            Pattern nonceLine = Pattern.compile("Nonce = ([0-9A-F]+)");
            Pattern ptLine = Pattern.compile("PT = ([0-9A-F]*)");
            Pattern adLine = Pattern.compile("AD = ([0-9A-F]*)");
            Pattern ctLine = Pattern.compile("CT = ([0-9A-F]+)"); // concatenates ciphertext and tag
            for (int i = 0; i < 1088; i++) {
                Matcher matcher = countLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                String count = matcher.group(1);
                matcher = keyLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                byte[] key = ByteOps.fromHex(matcher.group(1));
                matcher = nonceLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                byte[] nonce = ByteOps.fromHex(matcher.group(1));
                matcher = ptLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                String pt = matcher.group(1);
                byte[] plaintext = ByteOps.fromHex(pt);
                matcher = adLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                String ad = matcher.group(1);
                byte[] context = ByteOps.fromHex(ad);
                matcher = ctLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                String ct = matcher.group(1);
                byte[] ciphertext = ByteOps.fromHex(ct);
                reader.readLine(); // empty line
                vectors.add(dynamicContainer("P[" + pt + "]A[" + ad + "]", Arrays.asList(
                        dynamicTest("encrypt",
                                () -> assertArrayEquals(ciphertext, cipher.encrypt(key, nonce, context, plaintext))),
                        dynamicTest("decrypt",
                                () -> assertArrayEquals(plaintext, cipher.decrypt(key, nonce, context, ciphertext)))
                )));
            }
        } catch (IOException e) {
            fail(e);
        }
        return vectors;
    }
}
