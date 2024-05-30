/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "cms_utils.h"
#include "bc_signeddata_generator.h"
using namespace OHOS::SignatureTools;
bool CmsUtils::VerifySignDataWithUnsignedDataDigest(const std::vector<int8_t>& unsignedDataDigest,
    const std::vector<int8_t>& signedData)
{
    std::string unsignedDataDigest_(unsignedDataDigest.begin(), unsignedDataDigest.end());
    PKCS7Data p7Data(PKCS7_DETACHED_FLAGS);
    if (p7Data.Parse(signedData) < 0) {
        SIGNATURE_TOOLS_LOGE("verify pkcs7 signed data block bytes failed\n");
        return false;
    }
    if (p7Data.Verify(unsignedDataDigest_) < 0) {
        SIGNATURE_TOOLS_LOGE("verify pkcs7 signed datablock failed\n");
        return false;
    }
    return true;
}
bool CmsUtils::CheckOwnerID(const std::string& signature, const std::string& profileOwnerID,
    const std::string& profileType)
{
    std::string ownerID = profileOwnerID;
    if ("debug" == profileType)
        ownerID = "DEBUG_LIB_ID";
    int nid = CreateNIDFromOID(OWNERID_OID, OWNERID_OID_SHORT_NAME, OWNERID_OID_LONG_NAME);
    const unsigned char* data = reinterpret_cast<const unsigned char*>(signature.c_str());
    PKCS7* p7 = d2i_PKCS7(NULL, &data, static_cast<long>(signature.size()));
    if (p7 == nullptr) {
        SIGNATURE_TOOLS_LOGE("d2i_PKCS7 failed\n");
        return false;
    }
    STACK_OF(PKCS7_SIGNER_INFO)* signerInfosk = PKCS7_get_signer_info(p7);
    if (signerInfosk == nullptr) {
        PKCS7_free(p7);
        SIGNATURE_TOOLS_LOGE("PKCS7_get_signer_info failed\n");
        return true;
    }
    for (int i = 0; i < sk_PKCS7_SIGNER_INFO_num(signerInfosk); i++) {
        PKCS7_SIGNER_INFO* signerInfo = sk_PKCS7_SIGNER_INFO_value(signerInfosk, i);
        ASN1_TYPE* asn1Type = PKCS7_get_signed_attribute(signerInfo, nid);
        if (asn1Type == nullptr) {
            if ("debug" == profileType) {
                continue;
            }
            if (ownerID.empty()) {
                continue;
            } else {
                SIGNATURE_TOOLS_LOGE("app-identifier is not in the signature\n");
                PKCS7_free(p7);
                return false;
            }
        }
        if (ownerID.empty()) {
            SIGNATURE_TOOLS_LOGE("app-identifier in profile is null, but is not null in signature\n");
            PKCS7_free(p7);
            return false;
        }
        if (asn1Type->type == V_ASN1_UTF8STRING) {
            ASN1_STRING* result = asn1Type->value.asn1_string;
            std::string result_ownerID;
            result_ownerID.assign(reinterpret_cast<const char*>(ASN1_STRING_get0_data(result)),
                ASN1_STRING_length(result));
            if (ownerID != result_ownerID) {
                SIGNATURE_TOOLS_LOGE("app-identifier in signature is invalid\n");
                PKCS7_free(p7);
                return false;
            }
        }
    }
    PKCS7_free(p7);
    return true;
}
int CmsUtils::CreateNIDFromOID(const std::string& oid, const std::string& shortName,
    const std::string& longName)
{
    int nid = OBJ_txt2nid(oid.c_str());
    if (nid == NID_undef) {
        nid = OBJ_create(oid.c_str(), shortName.c_str(), longName.c_str());
    }
    return nid;
}