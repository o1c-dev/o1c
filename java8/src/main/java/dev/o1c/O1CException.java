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

import java.util.Collection;

public class O1CException extends RuntimeException {
    protected O1CException() {
        super();
    }

    public O1CException(String message) {
        super(message);
    }

    public O1CException(String message, Throwable cause) {
        super(message, cause);
    }

    public O1CException(Throwable cause) {
        super(cause);
    }

    public O1CException(String message, Collection<? extends Throwable> suppressedExceptions) {
        this(message);
        if (suppressedExceptions != null) {
            suppressedExceptions.forEach(this::addSuppressed);
        }
    }
}
