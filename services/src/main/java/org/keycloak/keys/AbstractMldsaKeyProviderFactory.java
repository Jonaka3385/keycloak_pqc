/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.keys;

import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.keycloak.provider.ProviderConfigProperty.LIST_TYPE;

public abstract class AbstractMldsaKeyProviderFactory implements KeyProviderFactory {

    protected static final String MLDSA_PRIVATE_KEY_KEY = "mldsaPrivateKey";
    protected static final String MLDSA_PUBLIC_KEY_KEY = "mldsaPublicKey";

    protected static ProviderConfigProperty MLDSA_PROPERTY = new ProviderConfigProperty("ML-DSA", "Generates ML-DSA keys",
            LIST_TYPE, Algorithm.MLDSA44, Algorithm.MLDSA65, Algorithm.MLDSA87);

    public final static ProviderConfigurationBuilder configurationBuilder() {
        return ProviderConfigurationBuilder.create()
                .property(Attributes.PRIORITY_PROPERTY)
                .property(Attributes.ENABLED_PROPERTY)
                .property(Attributes.ACTIVE_PROPERTY);
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        ConfigurationValidationHelper.check(model)
                .checkLong(Attributes.PRIORITY_PROPERTY, false)
                .checkBoolean(Attributes.ENABLED_PROPERTY, false)
                .checkBoolean(Attributes.ACTIVE_PROPERTY, false);
    }

    public static KeyPair generateMldsaKeyPair(int keySize) {
        String alg;
        if (keySize == 44) {
            alg = Algorithm.MLDSA44;
        } else if (keySize == 65) {
            alg = Algorithm.MLDSA65;
        } else if (keySize == 87) {
            alg = Algorithm.MLDSA87;
        } else {
            throw new IllegalStateException("Unknown key size: " + keySize);
        }
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(alg);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
