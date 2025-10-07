package org.keycloak.crypto.def;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.spec.ECParameterSpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.jboss.logging.Logger;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.crypto.CryptoConstants;
import org.keycloak.common.crypto.CertificateUtilsProvider;
import org.keycloak.common.crypto.ECDSACryptoProvider;
import org.keycloak.common.crypto.PemUtilsProvider;
import org.keycloak.common.crypto.UserIdentityExtractorProvider;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.common.util.KeystoreUtil.KeystoreFormat;
import org.keycloak.crypto.JavaAlgorithm;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PQCCryptoProvider implements CryptoProvider {

    private static final Logger log = Logger.getLogger(DefaultCryptoProvider.class);

    private final Provider bcpqcProvider;

    private Map<String, Object> providers = new ConcurrentHashMap<>();

    public PQCCryptoProvider() {
        // Make sure to instantiate this only once due it is expensive. And skip registration if already available in Java security providers (EG. due explicitly configured in java security file)
        Provider existingBcPqc = Security.getProvider(CryptoConstants.BC_PQC_PROVIDER_ID);
        this.bcpqcProvider = existingBcPqc == null ? new BouncyCastlePQCProvider() : existingBcPqc;

        //providers.put(CryptoConstants.MLDSA65, new BCMldsa65AlgorithmProvider());

        providers.put(CryptoConstants.MLKEM512, new BCMlkemAlgorithmProvider());
        providers.put(CryptoConstants.MLKEM768, new BCMlkemAlgorithmProvider());
        providers.put(CryptoConstants.MLKEM1024, new BCMlkemAlgorithmProvider());

        if (existingBcPqc == null) {
            Security.addProvider(this.bcpqcProvider);
            log.debugv("Loaded {0} security provider", this.bcpqcProvider.getClass().getName());
        } else {
            log.debugv("Security provider {0} already loaded", this.bcpqcProvider.getClass().getName());
        }
    }

    @Override
    public Provider getBouncyCastleProvider() {
        return bcpqcProvider;
    }

    @Override
    public int order() {
        return 200;
    }

    @Override
    public <T> T getAlgorithmProvider(Class<T> clazz, String algorithmType) {
        Object o = providers.get(algorithmType);
        if (o == null) {
            throw new IllegalArgumentException("Not found provider of algorithm type: " + algorithmType);
        }
        return clazz.cast(o);
    }

    @Override
    public CertificateUtilsProvider getCertificateUtils() {
        return new BCCertificateUtilsProvider();
    }

    @Override
    public PemUtilsProvider getPemUtils() {
        return new BCPemUtilsProvider();
    }

    @Override
    public ECParameterSpec createECParams(String curveName) throws UnsupportedOperationException {
        throw new UnsupportedOperationException("ECC not supported in PQC");
    }

    @Override
    public UserIdentityExtractorProvider getIdentityExtractorProvider() {
        return new BCUserIdentityExtractorProvider();
    }

    @Override
    public ECDSACryptoProvider getEcdsaCryptoProvider() throws UnsupportedOperationException {
        throw new UnsupportedOperationException("ECC not supported in PQC");
    }


    @Override
    public <T> T getOCSPProver(Class<T> clazz) {
        return clazz.cast(new BCOCSPProvider());
    }


    @Override
    public KeyPairGenerator getKeyPairGen(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        return KeyPairGenerator.getInstance(algorithm, BouncyIntegration.PROVIDER);
    }


    @Override
    public KeyFactory getKeyFactory(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        return KeyFactory.getInstance(algorithm, BouncyIntegration.PROVIDER);
    }


    @Override
    public Cipher getAesCbcCipher() throws UnsupportedOperationException {
        throw new UnsupportedOperationException("AES-CBC not supported in PQC");
    }

    @Override
    public Cipher getAesGcmCipher() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        return Cipher.getInstance("AES/GCM/NoPadding", BouncyIntegration.PROVIDER);
    }

    @Override
    public SecretKeyFactory getSecretKeyFact(String keyAlgorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        return SecretKeyFactory.getInstance(keyAlgorithm, BouncyIntegration.PROVIDER);
    }

    @Override
    public KeyStore getKeyStore(KeystoreFormat format) throws KeyStoreException, NoSuchProviderException {
        if (format == KeystoreFormat.JKS) {
            return KeyStore.getInstance(format.toString());
        } else {
            return KeyStore.getInstance(format.toString(), BouncyIntegration.PROVIDER);
        }
    }

    @Override
    public CertificateFactory getX509CertFactory() throws CertificateException, NoSuchProviderException {
        return CertificateFactory.getInstance("X.509", BouncyIntegration.PROVIDER);
    }

    @Override
    public CertStore getCertStore(CollectionCertStoreParameters certStoreParams) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        return CertStore.getInstance("Collection", certStoreParams, BouncyIntegration.PROVIDER);

    }


    @Override
    public CertPathBuilder getCertPathBuilder() throws NoSuchAlgorithmException, NoSuchProviderException {
        return CertPathBuilder.getInstance("PKIX", BouncyIntegration.PROVIDER);
    }

    @Override
    public Signature getSignature(String sigAlgName) throws NoSuchAlgorithmException, NoSuchProviderException {
        return Signature.getInstance(JavaAlgorithm.getJavaAlgorithm(sigAlgName), BouncyIntegration.PROVIDER);

    }

    @Override
    public SSLSocketFactory wrapFactoryForTruststore(SSLSocketFactory delegate) {
        return delegate;
    }
}
