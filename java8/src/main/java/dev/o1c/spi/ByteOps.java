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

    private ByteOps() {
        throw new UnsupportedOperationException();
    }
}
