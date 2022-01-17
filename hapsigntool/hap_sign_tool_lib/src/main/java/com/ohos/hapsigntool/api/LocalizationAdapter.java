/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.api;

import com.ohos.hapsigntool.api.model.Options;
import com.ohos.hapsigntool.error.CustomException;
import com.ohos.hapsigntool.error.ERROR;
import com.ohos.hapsigntool.key.KeyPairTools;
import com.ohos.hapsigntool.keystore.KeyStoreHelper;
import com.ohos.hapsigntool.utils.CertUtils;
import com.ohos.hapsigntool.utils.FileUtils;
import com.ohos.hapsigntool.utils.StringUtils;
import com.ohos.hapsigntool.utils.ValidateUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Localization adapter.
 *
 * @since 2021/12/28
 */
public class LocalizationAdapter {
    /**
     * check cert chain size
     */
    private static final int CERT_CHAIN_SIZE = 3;
    /**
     * Logger
     */
    private final Logger logger = LogManager.getLogger(LocalizationAdapter.class);
    /**
     * Params
     */
    private final Options options;
    /**
     * Operation of keystore
     */
    private KeyStoreHelper keyStoreHelper;

    /**
     * Constructor of LocalizationAdapter.
     *
     * @param options options
     */
    public LocalizationAdapter(Options options) {
        this.options = options;
    }

    /**
     * Get options.
     *
     * @return options
     */
    public Options getOptions() {
        return options;
    }

    private void initKeyStore() {
        // Avoid duplicated initialization
        if (keyStoreHelper != null) {
            return;
        }
        String keyStore = options.getString(Options.KEY_STORE_FILE, "");
        keyStoreHelper = new KeyStoreHelper(keyStore, options.getChars(Options.KEY_STORE_RIGHTS));
    }

    /**
     * Get KeyPair through key alias and password.
     *
     * @param autoCreate autoCreate
     * @return keyPair
     */
    public KeyPair getAliasKey(boolean autoCreate) {
        return getKeyPair(options.getString(Options.KEY_ALIAS),
                options.getChars(Options.KEY_RIGHTS), autoCreate);
    }

    /**
     * getIssuerAliasKey.
     *
     * @return param of issuerKeyAlias
     */
    public KeyPair getIssuerAliasKey() {
        return getKeyPair(options.getString(Options.ISSUER_KEY_ALIAS),
                options.getChars(Options.ISSUER_KEY_RIGHTS), false);
    }

    /**
     * Keystore has alias or not.
     *
     * @param alias alias
     * @return true or false
     */
    public boolean hasAlias(String alias) {
        if (keyStoreHelper == null) {
            initKeyStore();
        }
        return keyStoreHelper.hasAlias(alias);
    }

    /**
     * Error if not exist.
     *
     * @param alias alias
     */
    public void errorIfNotExist(String alias) {
        if (keyStoreHelper == null) {
            initKeyStore();
        }
        keyStoreHelper.errorIfNotExist(alias);
    }

    /**
     * Error on exist.
     *
     * @param alias alias
     */
    public void errorOnExist(String alias) {
        if (keyStoreHelper == null) {
            initKeyStore();
        }
        keyStoreHelper.errorOnExist(alias);
    }

    private KeyPair getKeyPair(String alias, char[] keyPwd, boolean autoCreate) {
        if (keyStoreHelper == null) {
            initKeyStore();
        }
        ValidateUtils.throwIfNotMatches(!StringUtils.isEmpty(alias), ERROR.ACCESS_ERROR, "Alias could not be empty");
        KeyPair keyPair = null;
        if (keyStoreHelper.hasAlias(alias)) {
            keyPair = keyStoreHelper.loadKeyPair(alias, keyPwd);
        } else {
            if (autoCreate) {
                options.required(Options.KEY_ALG, Options.KEY_SIZE);
                keyPair = KeyPairTools.generateKeyPair(options.getString(Options.KEY_ALG),
                        options.getInt(Options.KEY_SIZE));
                keyStoreHelper.store(alias, keyPwd, keyPair, null);
            }
        }
        ValidateUtils.throwIfNotMatches(keyPair != null, ERROR.NOT_SUPPORT_ERROR,
                String.format("%s: '%s' is not exist in %s", Options.KEY_ALIAS, alias,
                        options.getString(Options.KEY_STORE_FILE)));
        return keyPair;
    }

    /**
     * getProfileCert.
     *
     * @return profile cert
     */
    public List<X509Certificate> getSignCertChain() {
        String certPath = options.getString(Options.PROFILE_CERT_FILE);
        if (StringUtils.isEmpty(certPath)) {
            certPath = options.getString(Options.APP_CERT_FILE);
        }
        List<X509Certificate> certificates = getCertsFromFile(certPath, Options.PROFILE_CERT_FILE);
        ValidateUtils.throwIfNotMatches(certificates.size() == CERT_CHAIN_SIZE, ERROR.NOT_SUPPORT_ERROR,
                String.format("Profile cert '%s' must a cert chain", certPath));
        return certificates;
    }

    /**
     * getSubCaCertFile.
     *
     * @return sub ca cert
     */
    public X509Certificate getSubCaCertFile() {
        String certPath = options.getString(Options.SUB_CA_CERT_FILE);
        return getCertsFromFile(certPath, Options.SUB_CA_CERT_FILE).get(0);
    }

    /**
     * getCaCertFile.
     *
     * @return root ca cert
     */
    public X509Certificate getCaCertFile() {
        String certPath = options.getString(Options.CA_CERT_FILE);
        return getCertsFromFile(certPath, Options.CA_CERT_FILE).get(0);
    }

    /**
     * isOutFormChain.
     *
     * @return is out form chain
     */
    public boolean isOutFormChain() {
        String outForm = options.getString(Options.OUT_FORM, "certChain");
        return outForm.equals("certChain");
    }

    /**
     * Get certificates from file.
     *
     * @param certPath certPath
     * @param logTitle logTitle
     * @return certificates
     */
    public List<X509Certificate> getCertsFromFile(String certPath, String logTitle) {
        ValidateUtils.throwIfNotMatches(!StringUtils.isEmpty(certPath), ERROR.NOT_SUPPORT_ERROR,
                String.format("Params '%s' is not exist", logTitle));

        File certFile = new File(certPath);
        ValidateUtils.throwIfNotMatches(certFile.exists(), ERROR.FILE_NOT_FOUND,
                String.format("%s: '%s' is not exist", logTitle, certPath));
        List<X509Certificate> certificates = null;
        try {
            certificates = CertUtils.generateCertificates(FileUtils.readFile(certFile));
        } catch (IOException | CertificateException exception) {
            logger.debug(exception.getMessage(), exception);
            CustomException.throwException(ERROR.ACCESS_ERROR, exception.getMessage());
        }
        ValidateUtils.throwIfNotMatches(certificates != null && certificates.size() > 0, ERROR.READ_FILE_ERROR,
                String.format("Read fail from %s, bot found certificates", certPath));
        return certificates;
    }

    /**
     * getSignAlg.
     *
     * @return sign alg
     */
    public String getSignAlg() {
        return options.getString(Options.SIGN_ALG);
    }

    /**
     * isKeyUsageCritical.
     *
     * @return isKeyUsageCritical
     */
    public boolean isKeyUsageCritical() {
        return options.getBoolean(Options.KEY_USAGE_CRITICAL, true);
    }

    /**
     * isExtKeyUsageCritical.
     *
     * @return isExtKeyUsageCritical
     */
    public boolean isExtKeyUsageCritical() {
        return options.getBoolean(Options.EXT_KEY_USAGE_CRITICAL, true);
    }

    /**
     * isBasicConstraintsCa.
     *
     * @return isBasicConstraintsCa
     */
    public boolean isBasicConstraintsCa() {
        return options.getBoolean(Options.BASIC_CONSTRAINTS_CA, false);
    }

    /**
     * isBasicConstraintsCritical
     *
     * @return isBasicConstraintsCritical
     */
    public boolean isBasicConstraintsCritical() {
        return options.getBoolean(Options.BASIC_CONSTRAINTS_CRITICAL, false);
    }

    /**
     * getBasicConstraintsPathLen.
     *
     * @return BasicConstraintsPathLen
     */
    public int getBasicConstraintsPathLen() {
        return options.getInt(Options.BASIC_CONSTRAINTS_PATH_LEN);
    }

    /**
     * getExtKeyUsage.
     *
     * @return KeyPurposeId[] of ExtKeyUsage
     */
    public KeyPurposeId[] getExtKeyUsage() {
        return CertUtils.parseExtKeyUsage(options.getString(Options.EXT_KEY_USAGE));
    }

    /**
     * getKeyUsage.
     *
     * @return KeyUsage
     */
    public KeyUsage getKeyUsage() {
        return new KeyUsage(CertUtils.parseKeyUsage(options.getString(Options.KEY_USAGE)));
    }

    /**
     * getSubject.
     *
     * @return Subject
     */
    public X500Name getSubject() {
        String subject = options.getString(Options.SUBJECT);
        return CertUtils.buildDN(subject);
    }

    /**
     * getIssuer.
     * @return Issuer
     */
    public X500Name getIssuer() {
        String issuer = options.getString(Options.ISSUER, options.getString(Options.SUBJECT));
        return CertUtils.buildDN(issuer);
    }

    /**
     * getOutFile.
     *
     * @return OutFile
     */
    public String getOutFile() {
        return options.getString(Options.OUT_FILE);
    }

    /**
     * getInFile.
     *
     * @return InFile
     */
    public String getInFile() {
        String file = options.getString(Options.IN_FILE);
        ValidateUtils.throwIfNotMatches(new File(file).exists(), ERROR.FILE_NOT_FOUND,
                String.format("Required %s: '%s' not exist", Options.IN_FILE, file));
        return file;
    }

    /**
     * isRemoteSigner.
     *
     * @return isRemoteSigner
     */
    public boolean isRemoteSigner() {
        String mode = options.getString(Options.MODE, "localSign");
        return "remoteSign".equalsIgnoreCase(mode);
    }

    /**
     * Reset pwd to keep security
     */
    public void releasePwd() {
        resetChars(options.getChars(Options.KEY_STORE_RIGHTS));
        resetChars(options.getChars(Options.KEY_RIGHTS));
        resetChars(options.getChars(Options.ISSUER_KEY_RIGHTS));
    }

    private void resetChars(char[] chars) {
        if (chars == null) {
            return;
        }
        Arrays.fill(chars, (char) 0);
    }
}
