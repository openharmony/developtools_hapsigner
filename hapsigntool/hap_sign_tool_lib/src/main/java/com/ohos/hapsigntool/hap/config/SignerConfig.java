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

import com.ohos.hapsigntool.api.model.Options;
import com.ohos.hapsigntool.hap.sign.SignatureAlgorithm;
import com.ohos.hapsigntool.signer.ISigner;

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
    public Options options;

    /**
     * certificate chain used for sign hap
     */
    public List<X509Certificate> certificates;

    /**
     * certificate revocation list return from server
     */
    public List<X509CRL> x509CRLs;

    /**
     * Signature Algorithms used for sign hap
     */
    public List<SignatureAlgorithm> signatureAlgorithms;

    /**
     * parameters for sign hap
     */
    public Map<String, String> signParamMap = new HashMap<String, String>();

    /**
     * server interface for get signature
     */
    public void fillParameters(Map<String, String> params) {
        this.signParamMap = params;
    }

    /**
     * get signer
     */
    public ISigner getSigner() {
        return null;
    }
}
