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
 */

package dev.o1c.util;

import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayOutputStream;
import java.io.CharConversionException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.BufferOverflowException;
import java.util.Arrays;

import static java.lang.Integer.toUnsignedLong;

public final class ByteOps {
    public static void reverse(byte @NotNull [] buf) {
        for (int i = 0, j = buf.length - 1; i < j; i++, j--) {
            byte tmp = buf[i];
            buf[i] = buf[j];
            buf[j] = tmp;
        }
    }

    public static byte[] reverseCopyOf(byte @NotNull [] buf) {
        byte[] copy = buf.clone();
        reverse(copy);
        return copy;
    }

    public static byte[] concat(byte @NotNull [] @NotNull ... buffers) {
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

    public static int unpackIntBE(byte @NotNull [] buf, int off) {
        return (buf[off] & 0xff) << 24 | (buf[off + 1] & 0xff) << 16 | (buf[off + 2] & 0xff) << 8 | buf[off + 3] & 0xff;
    }

    public static int unpackIntLE(byte @NotNull [] buf, int off) {
        return buf[off] & 0xff | (buf[off + 1] & 0xff) << 8 | (buf[off + 2] & 0xff) << 16 | (buf[off + 3] & 0xff) << 24;
    }

    public static void unpackIntsLE(byte @NotNull [] buf, int off, int nrInts, int @NotNull [] dst, int dstOff) {
        for (int i = 0; i < nrInts; i++) {
            dst[dstOff + i] = unpackIntLE(buf, off + i * Integer.BYTES);
        }
    }

    public static int[] unpackIntsLE(byte @NotNull [] buf, int off, int nrInts) {
        int[] values = new int[nrInts];
        unpackIntsLE(buf, off, nrInts, values, 0);
        return values;
    }

    public static long unpackLongLE(byte @NotNull [] buf, int off) {
        return toUnsignedLong(unpackIntLE(buf, off)) |
                toUnsignedLong(unpackIntLE(buf, off + Integer.BYTES)) << 32;
    }

    public static void packIntLE(int value, byte @NotNull [] dst, int off) {
        dst[off] = (byte) value;
        dst[off + 1] = (byte) (value >>> 8);
        dst[off + 2] = (byte) (value >>> 16);
        dst[off + 3] = (byte) (value >>> 24);
    }

    public static void packIntsLE(int @NotNull [] values, int off, int nrInts, byte @NotNull [] dst, int dstOff) {
        for (int i = 0; i < nrInts; i++) {
            packIntLE(values[off + i], dst, dstOff + i * 4);
        }
    }

    public static void packLongLE(long value, byte @NotNull [] dst, int off) {
        packIntLE((int) value, dst, off);
        packIntLE((int) (value >>> 32), dst, off + Integer.BYTES);
    }

    public static byte[] fromHex(@NotNull CharSequence data) {
        return HEX_DECODER.decode(data);
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
