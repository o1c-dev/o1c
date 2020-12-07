/*
 * Copyright 2020 Matt Sicker
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dev.o1c.spi;

import java.io.ByteArrayOutputStream;
import java.io.CharConversionException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.Arrays;

public final class ByteOps {
    public static void reverse(byte[] buf) {
        for (int i = 0, j = buf.length - 1; i < j; i++, j--) {
            byte tmp = buf[i];
            buf[i] = buf[j];
            buf[j] = tmp;
        }
    }

    public static byte[] reverseCopyOf(byte[] buf) {
        byte[] copy = buf.clone();
        reverse(copy);
        return copy;
    }

    public static int unpackIntBE(byte[] buf, int off) {
        return (buf[off] & 0xff) << 24 | (buf[off + 1] & 0xff) << 16 | (buf[off + 2] & 0xff) << 8 | buf[off + 3] & 0xff;
    }

    public static int unpackIntLE(byte[] buf, int off) {
        return buf[off] & 0xff | (buf[off + 1] & 0xff) << 8 | (buf[off + 2] & 0xff) << 16 | (buf[off + 3] & 0xff) << 24;
    }

    public static void unpackIntsLE(byte[] buf, int off, int nrInts, int[] dst, int dstOff) {
        for (int i = 0; i < nrInts; i++) {
            dst[dstOff + i] = unpackIntLE(buf, off + i * 4);
        }
    }

    public static int[] unpackIntsLE(byte[] buf, int off, int nrInts) {
        int[] values = new int[nrInts];
        unpackIntsLE(buf, off, nrInts, values, 0);
        return values;
    }

    public static void packIntLE(int value, byte[] dst, int off) {
        dst[off] = (byte) value;
        dst[off + 1] = (byte) (value >>> 8);
        dst[off + 2] = (byte) (value >>> 16);
        dst[off + 3] = (byte) (value >>> 24);
    }

    public static void packIntsLE(int[] values, int off, int nrInts, byte[] dst, int dstOff) {
        for (int i = 0; i < nrInts; i++) {
            packIntLE(values[off + i], dst, dstOff + i * 4);
        }
    }

    public static byte[] fromHex(CharSequence data) {
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
