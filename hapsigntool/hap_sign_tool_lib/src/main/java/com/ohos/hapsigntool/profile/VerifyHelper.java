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

package com.ohos.hapsigntool.profile;

import com.ohos.hapsigntool.error.CustomException;
import com.ohos.hapsigntool.error.ERROR;
import com.ohos.hapsigntool.profile.model.Provision;
import com.ohos.hapsigntool.profile.model.VerificationResult;
import com.ohos.hapsigntool.utils.FileUtils;
import com.ohos.hapsigntool.utils.ValidateUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.util.Collection;

/**
 * Signed provision profile verifier.
 *
 * @since 2021/12/28
 */
public class VerifyHelper implements IProvisionVerifier {

    /**
     * LOGGER.
     */
    private static final Logger LOGGER = LogManager.getLogger(VerifyHelper.class);

    /**
     * Signed provision profile verifier.
     */
    public VerifyHelper() {
        // Empty constructor
    }

    /**
     * verify p7b content.
     *
     * @param p7b signed p7b content
     * @return result
     */
    @Override
    public VerificationResult verify(byte[] p7b) {
        VerificationResult result = new VerificationResult();

        try {
            CMSSignedData cmsSignedData = this.verifyPkcs(p7b);
            result.setContent(FileUtils.GSON.fromJson(new String((byte[]) (cmsSignedData
                    .getSignedContent().getContent()), StandardCharsets.UTF_8), Provision.class));
            result.setMessage("OK");
            result.setVerifiedPassed(true);
            return result;
        } catch (CustomException exception) {
            LOGGER.debug(exception.getMessage(), exception);
            result.setMessage("Failed to verify provision" + exception.getMessage());
            result.setVerifiedPassed(false);
            return result;
        }
    }

    @SuppressWarnings("unchecked")
    CMSSignedData verifyPkcs(byte[] p7b) {
        CMSSignedData cmsSignedData = null;
        try {
            cmsSignedData = new CMSSignedData(p7b);
            Store<X509CertificateHolder> store = cmsSignedData.getCertificates();
            cmsSignedData.verifySignatures((SignerId sid) -> {
                Collection<X509CertificateHolder> collection =
                        (Collection<X509CertificateHolder>) store.getMatches(sid);
                ValidateUtils.throwIfNotMatches(collection != null && collection.size() == 1, ERROR.VERIFY_ERROR,
                        "No matched cert or more than one matched certs: " + collection);
                X509CertificateHolder cert = collection.iterator().next();
                SignerInformationVerifier signInfoVerifier = null;
                try {
                    signInfoVerifier = (new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(cert);
                } catch (CertificateException exception) {
                    LOGGER.debug(exception.getMessage(), exception);
                    CustomException.throwException(ERROR.VERIFY_ERROR, "Failed to verify BC signatures: "
                            + exception.getMessage());
                }
                return signInfoVerifier;
            });
            return cmsSignedData;
        } catch (CMSException exception) {
            LOGGER.debug(exception.getMessage(), exception);
            CustomException.throwException(ERROR.VERIFY_ERROR, "Failed to verify BC signatures: "
                    + exception.getMessage());
        }
        return cmsSignedData;
    }
}
