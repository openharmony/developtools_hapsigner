/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
#include "bc_pkcs7_generator.h"
#include "signature_tools_log.h"
#include "pkcs7_data.h"
#include "signature_algorithm.h"
#include "bc_signeddata_generator.h"
#include "signer_config.h"
#include <vector>
#include "signature_tools_errno.h"
namespace OHOS::SignatureTools {
    BCPkcs7Generator::~BCPkcs7Generator()
    {
    }
    int BCPkcs7Generator::GenerateSignedData(const std::string& content,
                                             SignerConfig* signerConfig, std::string& ret)
    {
        std::string sigAlg;
        if (content.empty()) {
            SIGNATURE_TOOLS_LOGE("Verify digest is empty\n");
            return INVALIDPARAM_ERROR;
        }
        if (signerConfig == NULL) {
            SIGNATURE_TOOLS_LOGE("NULL signerConfig\n");
            return INVALIDPARAM_ERROR;
        }
        std::shared_ptr<ISigner> signer(signerConfig->GetSigner());
        if (signer == NULL) {
            SIGNATURE_TOOLS_LOGE("NULL signer\n");
            return INVALIDPARAM_ERROR;
        }
        if (BCSignedDataGenerator::GetSigAlg(signerConfig, sigAlg) < 0) {
            SIGNATURE_TOOLS_LOGE("get sigAlg failed\n");
            return INVALIDPARAM_ERROR;
        }
        if (PackagePKCS7(content, signer, NULL, sigAlg, ret) < 0) {
            SIGNATURE_TOOLS_LOGE("PackageSignedData error!\n");
            return GENERATEPKCS7_ERROR;
        }
        return 0;
    }
    int BCPkcs7Generator::PackagePKCS7(const std::string& content, std::shared_ptr<ISigner> signer,
        STACK_OF(X509_CRL)* crls, const std::string& sigAlg, std::string& ret)
    {
        PKCS7Data p7Data;
        if (p7Data.Sign(content, signer, sigAlg, ret) < 0) {
            SIGNATURE_TOOLS_LOGE("generate pkcs7 block failed\n");
            return PKCS7_SIGN_ERROR;
        }
        if (p7Data.Parse(ret) < 0) {
            SIGNATURE_TOOLS_LOGE("parse pkcs7 bytes failed\n");
            return PARSE_ERROR;
        }
        if (p7Data.Verify() < 0) {
            SIGNATURE_TOOLS_LOGE("verify pkcs7 block failed\n");
            return VERIFY_ERROR;
        }
        return 0;
    }
}