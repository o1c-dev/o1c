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

import dev.o1c.util.PublicKey;
import org.jetbrains.annotations.NotNull;

public interface SigncryptionKey {
    int signatureLength();

    int tagLength();

    @NotNull PublicKey publicKey();

    /*
    given sender keys W_a = w_a * G with id_a, and recipient keys W_b = w_b * G with id_b
    1. validate recipient certificate if used
    2. select random scalar r
    3. compute R = r * G where G is the generator element; let R = (x_r, y_r) in compressed x/y coordinates
    4. given key size in bits f (256 in ed25519), let x_r' = 2^ceil(f/2) + (x_r % 2^ceil(f/2))
    (or x_r' = 2^128 + (x_r % 2^128)
    compute K = (r + x_r' * w_a) * W_b, where K = (x_K, y_K) in compressed coordinates
    if K is the identity element, retry back to #2.
    let session key k = H(x_K || id_a || y_K || id_b)
    5. compute ciphertext C = E_k(M)
    6. compute t = H(C || x_r || id_a || y_r || id_b)
    compute s = (t * w_a - r) % n
    7. send signcrypted (R, C, s)
     */
    void signcrypt(
            @NotNull PublicKey recipient, byte @NotNull [] context, byte @NotNull [] in, int offset, int length,
            byte @NotNull [] out, int outOffset,
            byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] signature, int sigOffset);

    /*
    given signcrypted message (R, C, s)
    compute K = w_b * (R + x_r' * W_a) = (x_K, y_K)
    compute k = H(x_K || id_a || y_K || id_b)
    decrypt M = D_k(C)
    compute t = H(C || x_r || id_a || y_r || id_b)
    verify that s * G + R = t * W_a
     */
    void unsigncrypt(
            @NotNull PublicKey sender, byte @NotNull [] context, byte @NotNull [] in, int offset, int length,
            byte @NotNull [] tag, int tagOffset,
            byte @NotNull [] signature, int sigOffset,
            byte @NotNull [] out, int outOffset);
}
