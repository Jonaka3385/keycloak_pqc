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

package org.keycloak.crypto;

import org.keycloak.common.VerificationException;
import org.keycloak.models.KeycloakSession;

public class MLDSA65SignatureProvider implements SignatureProvider {

    private final KeycloakSession session;

    public MLDSA65SignatureProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public SignatureSignerContext signer() throws SignatureException {
        return new ServerMLDSA65SignatureSignerContext(session, Algorithm.MLDSA65);
    }

    @Override
    public SignatureSignerContext signer(KeyWrapper key) throws SignatureException {
        SignatureProvider.checkKeyForSignature(key, Algorithm.MLDSA65, KeyType.AKP);
        return new ServerMLDSA65SignatureSignerContext(key);
    }

    @Override
    public SignatureVerifierContext verifier(String kid) throws VerificationException {
        return new ServerMLDSA65SignatureVerifierContext(session, kid, Algorithm.MLDSA65);
    }

    @Override
    public SignatureVerifierContext verifier(KeyWrapper key) throws VerificationException {
        SignatureProvider.checkKeyForVerification(key, Algorithm.MLDSA65, KeyType.AKP);
        return new ServerMLDSA65SignatureVerifierContext(key);
    }

    @Override
    public boolean isAsymmetricAlgorithm() {
        return true;
    }
}
