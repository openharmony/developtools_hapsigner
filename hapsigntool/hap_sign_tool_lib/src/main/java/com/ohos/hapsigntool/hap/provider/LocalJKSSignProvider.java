/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.hap.provider;

import com.ohos.hapsigntool.api.model.Options;
import com.ohos.hapsigntool.hap.config.LocalJKSSignerConfig;
import com.ohos.hapsigntool.hap.config.SignerConfig;
import com.ohos.hapsigntool.hap.exception.InvalidParamsException;
import com.ohos.hapsigntool.hap.exception.MissingParamsException;
import com.ohos.hapsigntool.utils.FileUtils;
import com.ohos.hapsigntool.utils.ParamConstants;
import com.ohos.hapsigntool.utils.ParamProcessUtil;
import com.ohos.hapsigntool.utils.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.cert.CRL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

/**
 * Local keystore sign provider
 *
 * @since 2021/12/22
 */
public class LocalJKSSignProvider extends SignProvider {
    private static final Logger LOGGER = LogManager.getLogger(LocalJKSSignProvider.class);

    @Override
    public SignerConfig createV2SignerConfigs(List<X509Certificate> certificates, X509CRL crl)
            throws InvalidKeyException {
        return new LocalJKSSignerConfig(super.createV2SignerConfigs(certificates, crl));
    }

    @Override
    public X509CRL getCrl() {
        X509CRL crl = null;
        String crlPath = signParams.get(ParamConstants.PARAM_BASIC_CRL);
        if (crlPath == null || "".equals(crlPath)) {
            return crl;
        }
        try (FileInputStream input = new FileInputStream(new File(crlPath));) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CRL baseCrl = cf.generateCRL(input);
            if (!(baseCrl instanceof X509CRL)) {
                LOGGER.error("crl is not X509CRL");
                return crl;
            }
            crl = (X509CRL) baseCrl;
        } catch (IOException e) {
            LOGGER.error("read CRL File has IOException!");
            crl = null;
        } catch (GeneralSecurityException e) {
            LOGGER.error("Generate x509 CRL failed!");
            crl = null;
        }
        return crl;
    }

    /**
     * check keystore
     *
     * @throws MissingParamsException Exception occurs when the keystore file is not entered.
     */
    private void checkKeystore() throws MissingParamsException {
        if (!signParams.containsKey(ParamConstants.PARAM_LOCAL_JKS_KEYSTORE)) {
            throw new MissingParamsException("Missing parameter: " + ParamConstants.PARAM_LOCAL_JKS_KEYSTORE);
        }
    }

    /**
     * check keystore password
     *
     * @throws MissingParamsException Exception occurs when the keystore password is not right.
     */
    private void checkKeystorePassword() throws MissingParamsException {
        if (!signParams.containsKey(ParamConstants.PARAM_LOCAL_JKS_KEYSTORE_CODE)) {
            throw new MissingParamsException("Missing parameter: " + ParamConstants.PARAM_LOCAL_JKS_KEYSTORE_CODE);
        }
    }

    /**
     * check jks alias password
     *
     * @throws MissingParamsException Exception occurs when the key alias password is not right.
     */
    private void checkJKSAliasPassword() throws MissingParamsException {
        if (!signParams.containsKey(ParamConstants.PARAM_LOCAL_JKS_KEYALIAS_CODE)) {
            throw new MissingParamsException("Missing parameter: " + ParamConstants.PARAM_LOCAL_JKS_KEYALIAS_CODE);
        }
    }

    /**
     * check public cert
     *
     * @throws MissingParamsException Exception occurs when the key alias password is not right.
     * @throws InvalidParamsException Exception occurs when the key alias password is invalid.
     */
    private void checkPublicKeyPath() throws MissingParamsException, InvalidParamsException {
        if (!signParams.containsKey(ParamConstants.PARAM_LOCAL_PUBLIC_CERT)) {
            throw new MissingParamsException("Missing parameter: " + ParamConstants.PARAM_LOCAL_PUBLIC_CERT);
        }

        String publicCertsFile = signParams.get(ParamConstants.PARAM_LOCAL_PUBLIC_CERT);
        if (StringUtils.isEmpty(publicCertsFile)) {
            throw new MissingParamsException("empty-parameter : " + ParamConstants.PARAM_LOCAL_PUBLIC_CERT);
        }

        File publicKeyFile = new File(publicCertsFile);
        try {
            FileUtils.isValidFile(publicKeyFile);
        } catch (IOException e) {
            LOGGER.error("file is invalid: " + publicCertsFile + System.lineSeparator(), e);
            throw  new InvalidParamsException("Invalid file: " + publicCertsFile);
        }
    }

    @Override
    public void checkParams(Options options) throws InvalidParamsException, MissingParamsException {
        super.checkParams(options);
        String[] paramFileds = {
            ParamConstants.PARAM_LOCAL_JKS_KEYSTORE,
            ParamConstants.PARAM_LOCAL_JKS_KEYSTORE_CODE,
            ParamConstants.PARAM_LOCAL_JKS_KEYALIAS_CODE,
            ParamConstants.PARAM_LOCAL_PUBLIC_CERT
        };

        Set<String> paramSet = ParamProcessUtil.initParamField(paramFileds);

        for (String paramKey : options.keySet()) {
            if (paramSet.contains(paramKey)) {
                if (paramKey.endsWith("Pwd")) {
                    signParams.put(paramKey, new String(options.getChars(paramKey)));
                } else {
                    signParams.put(paramKey, options.getString(paramKey));
                }
            }
        }

        checkKeystore();
        checkKeystorePassword();
        checkJKSAliasPassword();
        checkPublicKeyPath();
    }
}
