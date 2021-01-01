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

package dev.o1c.modern.ed448;

import dev.o1c.primitive.VerificationKey;
import dev.o1c.primitive.VerificationKeyFactory;
import dev.o1c.util.ByteOps;
import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;

public class Ed448VerificationKeyFactory implements VerificationKeyFactory {
    private final KeyFactory keyFactory = Ed448.getKeyFactory();

    @Override
    public int keySize() {
        return 57;
    }

    @Override
    public VerificationKey parseKey(byte @NotNull [] key) {
        // little endian, high order bit specifies if x is odd or not
        // this bit of glue code inspired from:
        // https://bugs.openjdk.java.net/browse/JDK-8252595
        var bigEndianForm = ByteOps.reverseCopyOf(key);
        var xOdd = (bigEndianForm[0] & 0x80) != 0;
        bigEndianForm[0] &= 0x7f;
        var y = new BigInteger(bigEndianForm);
        var point = new EdECPoint(xOdd, y);
        try {
            return new Ed448VerificationKey(keyFactory.generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED448, point)));
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
