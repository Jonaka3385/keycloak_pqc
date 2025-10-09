package org.keycloak.authentication.requiredactions;

public class COSEAlgorithmIdentifierMLDSA {
    /**
     * temporary class for JOSE/COSE values
     * ML-DSA-44: -48
     * ML-DSA-65: -49
     * ML-DSA-87: -50
     * source: <a href="https://www.ietf.org/archive/id/draft-ietf-cose-dilithium-04.html">...</a>
     * !!Draft!!
     * !!Values can change!!
     * TODO: Delete when ML-DSA is available in webauthn4j
     * @param specificAlg which ML-DSA (44, 65, 87)
     * @return specified long value
     */
    public static long getValue(int specificAlg) {
        switch (specificAlg) {
            case 44:
                return -48;
            case 65:
                return -49;
            case 87:
                return -50;
            default:
                throw  new IllegalArgumentException("unknown ML-DSA Algorithm");
        }
    }
}
