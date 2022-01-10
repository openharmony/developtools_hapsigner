package com.ohos.hapsigntool.hap.config;

import com.ohos.hapsigntool.signer.ISigner;
import com.ohos.hapsigntool.signer.LocalSigner;
import com.ohos.hapsigntool.utils.ParamConstants;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.Map;

/**
 * get signature from local JKS
 *
 * @since 2021/12/28
 */
public class LocalHapSigner implements ISigner {
    private static final Logger LOG = LogManager.getLogger(LocalHapSigner.class);
    private Map<String, String> signParamMap;

    public LocalHapSigner(Map<String, String> signParamMap) {
        this.signParamMap = signParamMap;
    }


    public byte[] getSignature(byte[] data, String signatureAlg, AlgorithmParameterSpec second) {
        LOG.info("Compute signature by local jks mode!");
        byte[] signatureBytes = null;

        String keystore = this.signParamMap.get(ParamConstants.PARAM_LOCAL_JKS_KEYSTORE);
        String keystorePassword = this.signParamMap.get(ParamConstants.PARAM_LOCAL_JKS_KEYSTORE_CODE);
        String keyAlias = this.signParamMap.get(ParamConstants.PARAM_BASIC_PRIVATE_KEY);
        String keyAliasPassword = this.signParamMap.get(ParamConstants.PARAM_LOCAL_JKS_KEYALIAS_CODE);

        LOG.info(keystore);
        LOG.info(keystorePassword);
        LOG.info(keyAlias);
        LOG.info(keyAliasPassword);
        KeyStore keyStore;
        try (FileInputStream keyStoreStream = new FileInputStream(keystore);) {
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreStream, keystorePassword.toCharArray());
            Object obj = keyStore.getKey(keyAlias, keyAliasPassword.toCharArray());
            if (!(obj instanceof PrivateKey)) {
                LOG.error("hapsigntoolv2: error: Key Alias is not right");
                return signatureBytes;
            }
            PrivateKey privateKey = (PrivateKey)obj;
            LocalSigner signer = new LocalSigner(privateKey, null);
            signatureBytes = signer.getSignature(data, signatureAlg, second);
        } catch (KeyStoreException
                | NoSuchAlgorithmException
                | CertificateException
                | UnrecoverableKeyException
                | IOException e) {
            LOG.error("hapsigntoolv2: error: Store File error, possible reason:" + System.lineSeparator()
                    + "1. Please check whether Store Password or key Password is right," + System.lineSeparator()
                    + "2. Sign Alg does not match with Alg of private key, etc.");
            LOG.error("getSignature local JKS mod failed.", e);
        }
        return signatureBytes;
    }

    @Override
    public List<X509CRL> getCrls() {
        return null;
    };

    @Override
    public List<X509Certificate> getCertificates() {
        return null;
    };
}