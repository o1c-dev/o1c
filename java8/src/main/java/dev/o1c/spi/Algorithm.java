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

import java.security.CryptoPrimitive;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.function.Predicate;
import java.util.function.Supplier;

public enum Algorithm {
    ChaCha20Poly1305("ChaCha20-Poly1305", CryptoPrimitive.STREAM_CIPHER, 32, "1.2.840.113549.1.9.16.3.18"),
    X25519("X25519", CryptoPrimitive.KEY_AGREEMENT, 32, "1.3.101.110"),
    X448("X448", CryptoPrimitive.KEY_AGREEMENT, 56, "1.3.101.111"),
    Ed25519("Ed25519", CryptoPrimitive.SIGNATURE, 32, "1.3.101.112"),
    Ed448("Ed448", CryptoPrimitive.SIGNATURE, 57, "1.3.101.113");

    private final String algorithm;
    private final CryptoPrimitive cryptoPrimitive;
    private final int keySize;
    // https://www.rfc-editor.org/info/rfc8410
    private final String objectIdentifier;

    Algorithm(String algorithm, CryptoPrimitive cryptoPrimitive, int keySize, String objectIdentifier) {
        this.algorithm = algorithm;
        this.cryptoPrimitive = cryptoPrimitive;
        this.keySize = keySize;
        this.objectIdentifier = objectIdentifier;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public CryptoPrimitive getCryptoPrimitive() {
        return cryptoPrimitive;
    }

    public int getKeySize() {
        return keySize;
    }

    public String getObjectIdentifier() {
        return objectIdentifier;
    }

    public <T, F extends SecurityFactory<T>> F getFactory(Class<F> factoryType) {
        Predicate<F> p = factory -> algorithm.equals(factory.getAlgorithm());
        Supplier<String> errorMessageSupplier = () -> "No service providers found for algorithm '" + algorithm + "'";
        return getFactory(factoryType, p, errorMessageSupplier);
    }

    public <T, F extends SecurityFactory<T>> F getFactory(Class<F> factoryType, String provider) {
        Predicate<F> p = factory -> algorithm.equals(factory.getAlgorithm()) && provider.equals(factory.getProvider());
        Supplier<String> errorMessageSupplier =
                () -> "No service providers found for algorithm '" + algorithm + "' and provider '" + provider + "'";
        return getFactory(factoryType, p, errorMessageSupplier);
    }

    private <T, F extends SecurityFactory<T>> F getFactory(
            Class<F> factoryType, Predicate<F> predicate, Supplier<String> errorMessageSupplier) {
        Iterator<F> iterator = ServiceLoader.load(factoryType).iterator();
        List<Throwable> errors = null;
        while (iterator.hasNext()) {
            F factory;
            try {
                factory = iterator.next();
            } catch (ServiceConfigurationError error) {
                if (errors == null) {
                    errors = new ArrayList<>();
                }
                // unwrap our own exceptions
                if (error.getCause() instanceof InvalidProviderException) {
                    errors.add(error.getCause().getCause());
                } else {
                    errors.add(error);
                }
                continue;
            }
            if (predicate.test(factory)) {
                return factory;
            }
        }
        throw new O1CException(errorMessageSupplier.get(), errors);
    }
}
