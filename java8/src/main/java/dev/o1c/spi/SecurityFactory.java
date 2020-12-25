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
