package com.ohos.hapsigntool.hap.provider;

import com.ohos.hapsigntool.api.model.Options;
import com.ohos.hapsigntool.hap.config.RemoteSignerConfig;
import com.ohos.hapsigntool.hap.config.SignerConfig;
import com.ohos.hapsigntool.hap.exception.InvalidParamsException;
import com.ohos.hapsigntool.hap.exception.MissingParamsException;

import java.security.InvalidKeyException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

public class RemoteSignProvider extends SignProvider {
    @Override
    public SignerConfig createV2SignerConfigs(List<X509Certificate> certificates, X509CRL crl)
        throws InvalidKeyException {
        RemoteSignerConfig signerConfig = new RemoteSignerConfig();
        // add your config param here
        return signerConfig;
    }

    @Override
    public void checkParams(Options options) throws MissingParamsException, InvalidParamsException {
        super.checkParams(options);
    }

    @Override
    protected boolean checkInputCertMatchWithProfile(X509Certificate inputCert, X509Certificate certInProfile) {
        return inputCert == null ? false : inputCert.equals(certInProfile);
    }
}