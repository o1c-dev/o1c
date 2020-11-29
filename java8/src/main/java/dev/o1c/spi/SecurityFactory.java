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

import dev.o1c.O1CException;

import java.security.Provider;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.function.Predicate;
import java.util.function.Supplier;

public interface SecurityFactory<T> {
    T create();

    Algorithm getAlgorithm();

    Provider getProvider();

    static <T, S extends SecurityFactory<T>> S getInstance(
            Class<S> factoryType, Predicate<? super S> predicate, Supplier<String> errorMessageSupplier) {
        Iterator<S> iterator = ServiceLoader.load(factoryType).iterator();
        List<Throwable> errors = null;
        while (iterator.hasNext()) {
            S service;
            try {
                service = iterator.next();
            } catch (ServiceConfigurationError e) {
                if (errors == null) {
                    errors = new ArrayList<>();
                }
                errors.add(e.getCause() instanceof O1CException ? e.getCause() : e);
                continue;
            }
            if (predicate.test(service)) {
                return service;
            }
        }
        throw new O1CException(errorMessageSupplier.get(), errors);
    }
}
