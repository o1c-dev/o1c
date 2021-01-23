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

package dev.o1c.lwc.ascon;

import org.jetbrains.annotations.NotNull;

/**
 * Encapsulates the Ascon128 permutations. Ported from the reference C implementation.
 *
 * @see <a href="https://ascon.iaik.tugraz.at/files/asconv12.pdf">Ascon v1.2</a>
 */
class Ascon {
    private static final int MAX_ROUNDS = 12;

    private static void ascon(int rounds, long @NotNull [] s) {
        for (int round = MAX_ROUNDS - rounds; round < MAX_ROUNDS; round++) {
            int roundConstant = (15 - round << 4) | round;
            s[2] ^= roundConstant;
            // substitution layer
            s[0] ^= s[4];
            s[4] ^= s[3];
            s[2] ^= s[1];
            // start of keccak s-box
            long t0 = ~s[0], t1 = ~s[1], t2 = ~s[2], t3 = ~s[3], t4 = ~s[4];
            t0 &= s[1];
            t1 &= s[2];
            t2 &= s[3];
            t3 &= s[4];
            t4 &= s[0];
            s[0] ^= t1;
            s[1] ^= t2;
            s[2] ^= t3;
            s[3] ^= t4;
            s[4] ^= t0;
            // end of keccak s-box
            s[1] ^= s[0];
            s[0] ^= s[4];
            s[3] ^= s[2];
            s[2] = ~s[2];
            // linear diffusion layer
            s[0] ^= Long.rotateRight(s[0], 19) ^ Long.rotateRight(s[0], 28);
            s[1] ^= Long.rotateRight(s[1], 61) ^ Long.rotateRight(s[1], 39);
            s[2] ^= Long.rotateRight(s[2], 1) ^ Long.rotateRight(s[2], 6);
            s[3] ^= Long.rotateRight(s[3], 10) ^ Long.rotateRight(s[3], 17);
            s[4] ^= Long.rotateRight(s[4], 7) ^ Long.rotateRight(s[4], 41);
        }
    }

    static void ascon12(long @NotNull [] s) {
        ascon(12, s);
    }

    static void ascon6(long @NotNull [] s) {
        ascon(6, s);
    }

}
