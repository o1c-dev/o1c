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

package dev.o1c;

public interface Sealer {
    byte[] seal(byte[] data, byte[] context);

    default byte[] seal(byte[] data) {
        return seal(data, null);
    }

    byte[] unseal(byte[] sealedData, byte[] context);

    default byte[] unseal(byte[] sealedData) {
        return unseal(sealedData, null);
    }

    SealedData tokenSeal(byte[] data, byte[] context);

    default SealedData tokenSeal(byte[] data) {
        return tokenSeal(data, null);
    }

    byte[] tokenUnseal(byte[] encryptedData, byte[] token, byte[] context);

    default byte[] tokenUnseal(byte[] encryptedData, byte[] token) {
        return tokenUnseal(encryptedData, token, null);
    }
}
