package org.keycloak.common.crypto;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CryptoConstants {

    // JWE algorithms
    public static final String A128KW = "A128KW";
    public static final String RSA1_5 = "RSA1_5";
    public static final String RSA_OAEP = "RSA-OAEP";
    public static final String RSA_OAEP_256 = "RSA-OAEP-256";
    public static final String ECDH_ES = "ECDH-ES";
    public static final String ECDH_ES_A128KW = "ECDH-ES+A128KW";
    public static final String ECDH_ES_A192KW = "ECDH-ES+A192KW";
    public static final String ECDH_ES_A256KW = "ECDH-ES+A256KW";

    public static final String Dilithium2 = "Dilithium2";
    public static final String Dilithium3 = "Dilithium3";
    public static final String Dilithium5 = "Dilithium5";
    public static final String MLDSA44 = Dilithium2;
    public static final String MLDSA65 = Dilithium3;
    public static final String MLDSA87 = Dilithium5;

    // Constant for the OCSP provider
    // public static final String OCSP = "OCSP";

    /** Name of Java security provider used with non-fips BouncyCastle. Should be used in non-FIPS environment */
    public static final String BC_PROVIDER_ID = "BC";
    public static final String BC_PQC_PROVIDER_ID = "BCPQC";

    /** Name of Java security provider used with fips BouncyCastle. Should be used in FIPS environment */
    public static final String BCFIPS_PROVIDER_ID = "BCFIPS";
}
