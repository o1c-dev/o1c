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

package dev.o1c.bc;

import dev.o1c.spi.Algorithm;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

class PrivateKeyCodec extends CurveCodec<PrivateKey> {
    private final AlgorithmIdentifier identifier;

    PrivateKeyCodec(Algorithm algorithm, KeyFactory keyFactory) {
        super(algorithm, keyFactory);
        identifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(algorithm.getObjectIdentifier()));
    }

    @Override
    public byte[] encode(PrivateKey key) {
        try {
            PKCS8EncodedKeySpec keySpec = keyFactory.getKeySpec(key, PKCS8EncodedKeySpec.class);
            PrivateKeyInfo keyInfo = PrivateKeyInfo.getInstance(keySpec.getEncoded());
            return keyInfo.getPrivateKey().getOctets();
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public PrivateKey decode(byte[] keyData) {
        if (keyData.length != getKeySize()) {
            throw new IllegalArgumentException("Invalid key size; expected " + getKeySize() + " bytes but got " + keyData.length);
        }
        try {
            PrivateKeyInfo keyInfo = new PrivateKeyInfo(identifier, new DEROctetString(keyData));
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyInfo.getEncoded());
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException | IOException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
