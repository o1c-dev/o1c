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

package dev.o1c.internal;

interface GroupOperations {
    interface Scalar<S extends Scalar<S>> {
        byte[] toByteArray();

        S multiplyAndAdd(S multiplicand, S addend);

        S multiplyAndSubtract(S multiplicand, S difference);
    }

    interface Element<S extends Scalar<S>, E extends Element<S, E>> {
        byte[] toByteArray();

        E add(E addend);

        E multiply(S multiplicand);

        boolean isEqual(E element);
    }
}
