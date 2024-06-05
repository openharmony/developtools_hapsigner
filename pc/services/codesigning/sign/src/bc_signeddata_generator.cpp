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
#include "bc_signeddata_generator.h"
#include "signature_tools_log.h"
#include "pkcs7_data.h"
#include "signature_algorithm.h"
#include "local_signer.h"
#include "signer_config.h"
#include <vector>
#include "signature_tools_errno.h"
#include "constant.h"
namespace OHOS::SignatureTools {
    const std::string OWNERID_OID = SIGNED_ID;  // SIGNED_ID
    const std::string OWNERID_OID_SHORT_NAME = "ownerID";
    const std::string OWNERID_OID_LONG_NAME = "Code Signature Owner ID";
    int BCSignedDataGenerator::GenerateSignedData(const std::string& content,
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
        std::shared_ptr<ISigner> signer = signerConfig->GetSigner();
        if (signer == NULL) {
            SIGNATURE_TOOLS_LOGE("NULL signer\n");
            return INVALIDPARAM_ERROR;
        }
        if (GetSigAlg(signerConfig, sigAlg) < 0) {
            SIGNATURE_TOOLS_LOGE("get sigAlg failed\n");
            return INVALIDPARAM_ERROR;
        }
        if (PackageSignedData(content, signer, NULL, sigAlg, ret) < 0) {
            SIGNATURE_TOOLS_LOGE("PackageSignedData error!\n");
            return GENERATEPKCS7_ERROR;
        }
        return 0;
    }
    void BCSignedDataGenerator::SetOwnerId(const std::string& ownerID)
    {
        this->ownerID = ownerID;
    }
    int BCSignedDataGenerator::PackageSignedData(const std::string& content,
        std::shared_ptr<ISigner> signer, STACK_OF(X509_CRL)* crls,
        const std::string& sigAlg, std::string& ret)
    {
        PKCS7Data p7Data(PKCS7_DETACHED_FLAGS);
        std::vector<PKCS7Attr> attrs;
        if (ownerID.empty() == false) {
            if (AddOwnerID(attrs, this->ownerID) < 0) {
                SIGNATURE_TOOLS_LOGE("create ownerIDOid failed\n");
                return INVALIDPARAM_ERROR;
            }
        }
        //生成pkcs7
        if (p7Data.Sign(content, signer, sigAlg, ret, attrs) < 0) {
            SIGNATURE_TOOLS_LOGE("generate pkcs7 signed data block failed\n");
            return PKCS7_SIGN_ERROR;
        }
        //解析后验证
        if (p7Data.Parse(ret) < 0) {
            SIGNATURE_TOOLS_LOGE("verify pkcs7 signed data block bytes failed\n");
            return PARSE_ERROR;
        }
        if (p7Data.Verify(content) < 0) {
            SIGNATURE_TOOLS_LOGE("verify pkcs7 signed datablock failed\n");
            return VERIFY_ERROR;
        }
        return 0;
    }
    int BCSignedDataGenerator::GetSigAlg(SignerConfig* signerConfig, std::string& sigAlg)
    {
        std::vector<SignatureAlgorithmClass> sigs = signerConfig->GetSignatureAlgorithms();
        if (sigs.size() != 1) {
            SIGNATURE_TOOLS_LOGE("sigAlg count not equal 1\n");
            return INVALIDPARAM_ERROR;
        }
        SignatureAlgorithmClass signatureAlg = sigs[0];
        if (signatureAlg.id == SignatureAlgorithmId::ECDSA_WITH_SHA256) {
            sigAlg = "SHA256withECDSA";
        } else if (signatureAlg.id == SignatureAlgorithmId::ECDSA_WITH_SHA384) {
            sigAlg = "SHA384withECDSA";
        } else {
            SIGNATURE_TOOLS_LOGE("unsupport sigAlg\n");
            return NOT_SUPPORT_ERROR;
        }
        return 0;
    }
    int BCSignedDataGenerator::CreateNIDFromOID(const std::string& oid, const std::string& shortName,
        const std::string& longName)
    {
        int nid = OBJ_txt2nid(oid.c_str());
        if (nid == NID_undef) {
            nid = OBJ_create(oid.c_str(), shortName.c_str(), longName.c_str());
        }
        return nid;
    }
    int BCSignedDataGenerator::AddOwnerID(std::vector<PKCS7Attr>& attrs, const std::string& ownerID)
    {
        PKCS7Attr attr;
        int nid = CreateNIDFromOID(OWNERID_OID, OWNERID_OID_SHORT_NAME, OWNERID_OID_LONG_NAME);
        if (nid == NID_undef) {
            return CREATE_NID_ERROR;
        }
        ASN1_STRING* ownerIDAsn1 = ASN1_STRING_new();
        if (ownerIDAsn1 == NULL) {
            printf("asn1 string create error!\n");
            return MEMORY_ALLOC_ERROR;
        }
        ASN1_STRING_set(ownerIDAsn1, ownerID.c_str(), ownerID.length());
        attr.nid = nid;
        attr.atrtype = V_ASN1_UTF8STRING;
        attr.value = ownerIDAsn1;
        attrs.push_back(attr);
        return 0;
    }
}