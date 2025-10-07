package org.keycloak.crypto.def;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.jose.jwe.JWEHeader;
import org.keycloak.jose.jwe.JWEHeader.JWEHeaderBuilder;
import org.keycloak.jose.jwe.JWEKeyStorage;
import org.keycloak.jose.jwe.alg.JWEAlgorithmProvider;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;
import org.keycloak.jose.jwk.AKPPublicJWK;
import org.keycloak.common.util.Base64Url;

public class BCMlkemAlgorithmProvider implements JWEAlgorithmProvider {
    @Override
    public byte[] decodeCek(byte[] encodedCek, Key encryptionKey, JWEHeader header, JWEEncryptionProvider encryptionProvider) throws Exception {
        return new byte[0];
    }

    @Override
    public byte[] encodeCek(JWEEncryptionProvider encryptionProvider, JWEKeyStorage keyStorage, Key encryptionKey, JWEHeaderBuilder headerBuilder) throws Exception {
        return new byte[0];
    }
}
