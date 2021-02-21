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

package dev.o1c.modern.ristretto255;

import dev.o1c.spi.CertificateFactory;
import dev.o1c.spi.InvalidSignatureException;
import dev.o1c.spi.PrivateKey;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertThrows;

class Ristretto255B3Test {
    @Test
    void signatureSmokeTest() {
        CertificateFactory factory = new Ristretto255B3CertificateFactory();
        PrivateKey key = factory.generateKey();
        byte[] message = "Hello, world!".getBytes(StandardCharsets.UTF_8);
        byte[] signature = key.sign(message);
        key.verify(message, signature);
        signature[0] >>>= 3;
        signature[1] = (byte) ~signature[1];
        assertThrows(InvalidSignatureException.class, () -> key.verify(message, signature));
    }
}
