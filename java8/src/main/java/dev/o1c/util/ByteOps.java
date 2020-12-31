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

package dev.o1c.util;

import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayOutputStream;
import java.io.CharConversionException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Provides various utilities for manipulating byte arrays.
 */
public final class ByteOps {
    public static void reverse(byte @NotNull [] buf) {
        for (int i = 0, j = buf.length - 1; i < j; i++, j--) {
            byte tmp = buf[i];
            buf[i] = buf[j];
            buf[j] = tmp;
        }
    }

    public static byte @NotNull [] reverseCopyOf(byte @NotNull [] buf) {
        byte[] copy = buf.clone();
        reverse(copy);
        return copy;
    }

    public static byte @NotNull [] concat(byte @NotNull [] @NotNull ... buffers) {
        int size = 0;
        for (byte[] buffer : buffers) {
            size += buffer.length;
            if (size < 0) {
                throw new BufferOverflowException();
            }
        }
        byte[] buf = new byte[size];
        int off = 0;
        for (byte[] buffer : buffers) {
            System.arraycopy(buffer, 0, buf, off, buffer.length);
            off += buffer.length;
        }
        return buf;
    }

    public static void overwriteWithZeroes(byte @NotNull [] buf) {
        overwriteWithZeroes(buf, 0, buf.length);
    }

    public static void overwriteWithZeroes(byte @NotNull [] buf, int off, int len) {
        Arrays.fill(buf, off, off + len, (byte) 0);
    }

    public static int unpackIntLE(byte @NotNull [] buf, int off) {
        return unpackIntLE(buf, off, Integer.BYTES);
    }

    public static int unpackIntLE(byte @NotNull [] buf, int off, int len) {
        int ret = 0;
        for (int i = 0; i < len; i++) {
            ret |= (buf[off + i] & 0xff) << i * Byte.SIZE;
        }
        return ret;
    }

    public static void unpackIntsLE(byte @NotNull [] buf, int off, int nrInts, int @NotNull [] dst, int dstOff) {
        while (nrInts-- > 0) {
            dst[dstOff++] = unpackIntLE(buf, off);
            off += Integer.BYTES;
        }
    }

    public static int[] unpackIntsLE(byte @NotNull [] buf, int off, int nrInts) {
        int[] values = new int[nrInts];
        unpackIntsLE(buf, off, nrInts, values, 0);
        return values;
    }

    public static long unpackLongLE(byte @NotNull [] buf, int off) {
        return Integer.toUnsignedLong(unpackIntLE(buf, off)) |
                Integer.toUnsignedLong(unpackIntLE(buf, off + Integer.BYTES)) << Integer.SIZE;
    }

    public static long unpackLongBE(byte @NotNull [] buf, int off) {
        return unpackLongBE(buf, off, Long.BYTES);
    }

    public static long unpackLongBE(byte @NotNull [] buf, int off, int len) {
        long ret = 0;
        for (int i = 0; i < len; i++) {
            ret |= Byte.toUnsignedLong(buf[off + i]) << 56 - i * Byte.SIZE;
        }
        return ret;
    }

    public static void unpackLongsBE(byte @NotNull [] buf, int off, int nrLongs, long @NotNull [] dst, int dstOff) {
        while (nrLongs-- > 0) {
            dst[dstOff++] = unpackLongBE(buf, off);
            off += Long.BYTES;
        }
    }

    public static void packIntLE(int value, byte @NotNull [] dst, int off) {
        packIntLE(value, dst, off, Integer.BYTES);
    }

    public static void packIntLE(int value, byte @NotNull [] dst, int off, int len) {
        for (int i = 0; i < len; i++) {
            dst[off + i] = (byte) (value >>> i * Byte.SIZE);
        }
    }

    public static void packIntsLE(int @NotNull [] values, int off, int nrInts, byte @NotNull [] dst, int dstOff) {
        while (nrInts-- > 0) {
            packIntLE(values[off++], dst, dstOff);
            dstOff += Integer.BYTES;
        }
    }

    public static void packIntBE(int value, byte @NotNull [] dst, int off) {
        dst[off++] = (byte) (value >>> 24);
        dst[off++] = (byte) (value >>> 16);
        dst[off++] = (byte) (value >>> 8);
        dst[off] = (byte) value;
    }

    public static void packLongLE(long value, byte @NotNull [] dst, int off) {
        packIntLE((int) value, dst, off);
        packIntLE((int) (value >>> Integer.SIZE), dst, off + Integer.BYTES);
    }

    public static void packLongBE(long value, byte @NotNull [] dst, int off) {
        packLongBE(value, dst, off, Long.BYTES);
    }

    public static void packLongBE(long value, byte @NotNull [] dst, int off, int len) {
        for (int i = 0; i < len; i++) {
            dst[off + i] = (byte) (value >> 56 - i * Byte.SIZE);
        }
    }

    public static void packLongsBE(long @NotNull [] values, int off, int nrLongs, byte @NotNull [] dst, int dstOff) {
        while (nrLongs-- > 0) {
            packLongBE(values[off++], dst, dstOff);
            dstOff += Long.BYTES;
        }
    }

    public static byte @NotNull [] fromHex(@NotNull CharSequence data) {
        return HEX_DECODER.decode(data);
    }

    public static @NotNull String toHex(byte @NotNull [] buf) {
        return toHex(buf, 0, buf.length);
    }

    /**
     * Converts a slice of bytes into lowercase hexadecimal ASCII characters.
     */
    public static @NotNull String toHex(byte @NotNull [] buf, int off, int len) {
        byte[] hex = new byte[len * 2];
        for (int i = 0; i < len; i++) {
            int c = buf[off + i] & 0xf;
            int b = (buf[off + i] & 0xf0) >> 4;
            int x = 87 + c + (c - 10 >> 8 & -39) << 8 |
                    87 + b + (b - 10 >> 8 & -39);
            hex[i * 2] = (byte) x;
            hex[i * 2 + 1] = (byte) (x >> 8);
        }
        return new String(hex, StandardCharsets.US_ASCII);
    }

    private static final HexDecoder HEX_DECODER = new HexDecoder();

    // adapted from BouncyCastle
    private static class HexDecoder {
        private final byte[] decodeTable;

        private HexDecoder() {
            decodeTable = new byte[128]; // hex chars are all in ASCII range
            Arrays.fill(decodeTable, (byte) 0xff);
            decodeTable['0'] = 0;
            decodeTable['1'] = 1;
            decodeTable['2'] = 2;
            decodeTable['3'] = 3;
            decodeTable['4'] = 4;
            decodeTable['5'] = 5;
            decodeTable['6'] = 6;
            decodeTable['7'] = 7;
            decodeTable['8'] = 8;
            decodeTable['9'] = 9;
            decodeTable['a'] = 10;
            decodeTable['b'] = 11;
            decodeTable['c'] = 12;
            decodeTable['d'] = 13;
            decodeTable['e'] = 14;
            decodeTable['f'] = 15;
            decodeTable['A'] = 10;
            decodeTable['B'] = 11;
            decodeTable['C'] = 12;
            decodeTable['D'] = 13;
            decodeTable['E'] = 14;
            decodeTable['F'] = 15;
        }

        byte[] decode(CharSequence data) {
            if (data.length() == 0) {
                return new byte[0];
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try {
                decodeTo(data, out);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            return out.toByteArray();
        }

        void decodeTo(CharSequence data, OutputStream out) throws IOException {
            if (data.length() == 0) {
                return;
            }
            int end = data.length();
            // stripRight
            while (end > 0 && Character.isWhitespace(data.charAt(end - 1))) {
                end--;
            }
            byte[] buf = new byte[32];
            int off = 0;
            int i = 0;
            while (i < end) {
                // stripLeft
                while (i < end && Character.isWhitespace(data.charAt(i))) {
                    i++;
                }
                byte hi = decodeTable[data.charAt(i++)];
                // stripLeft
                while (i < end && Character.isWhitespace(data.charAt(i))) {
                    i++;
                }
                byte lo = decodeTable[data.charAt(i++)];
                if ((hi | lo) < 0) {
                    throw new CharConversionException("Encountered non-whitespace non-hexadecimal character in input");
                }
                buf[off++] = (byte) (hi << 4 | lo);
                // flush
                if (off == buf.length) {
                    out.write(buf);
                    off = 0;
                }
            }
            // final flush
            if (off > 0) {
                out.write(buf, 0, off);
            }
        }
    }

    private ByteOps() {
        throw new UnsupportedOperationException();
    }
}
