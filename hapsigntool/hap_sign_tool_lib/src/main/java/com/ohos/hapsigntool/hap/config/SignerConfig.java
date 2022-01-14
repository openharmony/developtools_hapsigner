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

package com.ohos.hapsigntool.hap.config;

import com.ohos.hapsigntool.api.LocalizationAdapter;
import com.ohos.hapsigntool.api.model.Options;
import com.ohos.hapsigntool.hap.sign.SignatureAlgorithm;
import com.ohos.hapsigntool.signer.ISigner;
import com.ohos.hapsigntool.signer.SignerFactory;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Sign config super class
 *
 * @since 2021-12-13
 */
public class SignerConfig {
    /**
     * params inputted by users
     */
    private Options options;

    /**
     * certificate chain used for sign hap
     */
    private List<X509Certificate> certificates;

    /**
     * certificate revocation list return from server
     */
    private List<X509CRL> x509CRLs;

    /**
     * Signature Algorithms used for sign hap
     */
    private List<SignatureAlgorithm> signatureAlgorithms;

    /**
     * parameters for sign hap
     */
    private Map<String, String> signParamMap = new HashMap<String, String>();

    /**
     * Get options.
     *
     * @return options
     */
    public Options getOptions() {
        return options;
    }

    /**
     * set options.
     */
    public void setOptions(Options options) {
        this.options = options;
    }

    /**
     * Get certificates.
     *
     * @return certificates
     */
    public List<X509Certificate> getCertificates() {
        return certificates;
    }

    /**
     * set certificate
     */
    public void setCertificates(List<X509Certificate> certificates) {
        this.certificates = certificates;
    }

    /**
     * get crl
     *
     * @return crl list
     */
    public List<X509CRL> getX509CRLs() {
        return x509CRLs;
    }

    /**
     * set crl
     */
    public void setX509CRLs(List<X509CRL> crls) {
        this.x509CRLs = crls;
    }

    /**
     * get signature algorithm
     *
     * @return signature algorithm
     */
    public List<SignatureAlgorithm> getSignatureAlgorithms() {
        return signatureAlgorithms;
    }

    /**
     * set signature algorithm
     */
    public void setSignatureAlgorithms(List<SignatureAlgorithm> signatureAlgorithms) {
        this.signatureAlgorithms = signatureAlgorithms;
    }

    /**
     * get param map
     *
     * @return param map
     */
    public Map<String, String> getSignParamMap() {
        return this.signParamMap;
    }

    /**
     * set param map
     */
    public void fillParameters(Map<String, String> params) {
        this.signParamMap = params;
    }

    /**
     * get signer
     */
    public ISigner getSigner() {
        return new SignerFactory().getSigner(new LocalizationAdapter(options));
    }
}
