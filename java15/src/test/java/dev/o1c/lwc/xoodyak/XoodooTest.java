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

import dev.o1c.util.ByteOps;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.TestFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

class XoodooTest {

    /*
    test vectors generated using reference Xoodyak C source code and the following generator code:

    #include <stdio.h>
    #include "Xoodoo-SnP.h"

    void print_bstr(const char *label, const unsigned char *data, unsigned long long length) {
        printf("%s", label);
        for (unsigned long long i = 0; i < length; i++) {
            printf("%02X", data[i]);
        }
        printf("\n");
    }

    int main() {
        unsigned char initial_state[48];
        for (unsigned long long i = 0; i < sizeof initial_state; i++) {
            initial_state[i] = i;
        }
        unsigned char state[48];
        Xoodoo_Initialize(state);
        for (unsigned long long i = 0; i < 1024; i++) {
            for (unsigned long long j = 0; j < i; j++) {
                ++initial_state[j % 48];
            }
            printf("Count = %ull\n", i + 1);
            print_bstr("Start = ", initial_state, sizeof initial_state);
            Xoodoo_OverwriteBytes(state, initial_state, 0, sizeof initial_state);
            Xoodoo_Permute_12rounds(state);
            print_bstr("End = ", state, sizeof state);
            printf("\n");
        }
    }
     */

    @TestFactory
    List<DynamicNode> loadTests() {
        var tests = new ArrayList<DynamicNode>(1024);
        var stream = getClass().getResourceAsStream("xoodoo.txt.gz");
        assertNotNull(stream);
        try (var reader = new BufferedReader(new InputStreamReader(new GZIPInputStream(stream), StandardCharsets.UTF_8))) {
            var countLine = Pattern.compile("Count = (\\d+)");
            var startLine = Pattern.compile("Start = ([0-9A-F]{96})");
            var endLine = Pattern.compile("End = ([0-9A-F]{96})");
            Xoodoo xoodoo = new Xoodoo();
            for (int i = 0; i < 1024; i++) {
                var matcher = countLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                var count = matcher.group(1);
                matcher = startLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                var start = ByteOps.fromHex(matcher.group(1));
                matcher = endLine.matcher(reader.readLine());
                assertTrue(matcher.matches());
                var end = ByteOps.fromHex(matcher.group(1));
                var actual = new byte[end.length];
                // blank line
                reader.readLine();
                tests.add(dynamicTest("state#" + count, () -> {
                    xoodoo.reset();
                    xoodoo.addBytes(start, 0, start.length);
                    xoodoo.permute();
                    xoodoo.extractBytes(actual, 0, actual.length);
                    assertArrayEquals(end, actual);
                }));
            }
        } catch (IOException e) {
            fail(e);
        }
        return tests;
    }
}
