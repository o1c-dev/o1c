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

import javax.crypto.SecretKey;

public interface Cipher {
    SecretKey newKey();

    byte[] newNonce();

    byte[] encrypt(byte[] key, byte[] nonce, byte[] plaintext);

    byte[] encrypt(SecretKey key, byte[] nonce, byte[] plaintext);

    byte[] encryptAAD(byte[] key, byte[] nonce, byte[] plaintext, byte[] additionalAuthenticatedData);

    byte[] encryptAAD(SecretKey key, byte[] nonce, byte[] plaintext, byte[] additionalAuthenticatedData);

    byte[] decrypt(byte[] key, byte[] nonce, byte[] ciphertext);

    byte[] decrypt(SecretKey key, byte[] nonce, byte[] ciphertext);

    byte[] decryptAAD(byte[] key, byte[] nonce, byte[] ciphertext, byte[] additionalAuthenticatedData);

    byte[] decryptAAD(SecretKey key, byte[] nonce, byte[] ciphertext, byte[] additionalAuthenticatedData);
}
