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

public class CryptoHashTest {
    public static @NotNull List<DynamicNode> loadHashTests(@NotNull String testResource, @NotNull CryptoHash hash) {
        var vectors = new ArrayList<DynamicNode>(1024);
        var stream = hash.getClass().getResourceAsStream(testResource);
        assertNotNull(stream, "No test resource found: " + testResource);
        try (var reader = new BufferedReader(new InputStreamReader(new GZIPInputStream(stream), StandardCharsets.UTF_8))) {
            var countLine = Pattern.compile("Count = (\\d+)");
            var msgLine = Pattern.compile("Msg = ([0-9A-F]*)");
            var hashLine = Pattern.compile("MD = ([0-9A-F]{64})");
            for (int i = 0; i < 1024; i++) {
                var matcher = countLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                var count = matcher.group(1);
                matcher = msgLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                var msg = matcher.group(1);
                var message = ByteOps.fromHex(msg);
                matcher = hashLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                var md = ByteOps.fromHex(matcher.group(1));
                reader.readLine(); // empty line
                vectors.add(dynamicContainer("M[" + msg + "]", List.of(
                        dynamicTest("hash", () -> assertArrayEquals(md, hash.hash(message))),
                        dynamicTest("reset/update/finish", () -> {
                            hash.reset();
                            hash.update(message);
                            assertArrayEquals(md, hash.finish());
                        })
                        // TODO: test out hashing per-byte and other partial hashing
                )));
            }
        } catch (IOException e) {
            fail(e);
        }
        return vectors;
    }
}
