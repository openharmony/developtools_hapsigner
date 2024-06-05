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
#ifndef SIGNERTOOLS_BC_SIGNEDDATA_GENERATOR_H
#define SIGNERTOOLS_BC_SIGNEDDATA_GENERATOR_H
#include "signeddata_generator.h"
#include <openssl/x509.h>
#include <string>
#include <vector>
#include <memory>
namespace OHOS::SignatureTools {
    extern const std::string OWNERID_OID;  // SIGNED_ID
    extern const std::string OWNERID_OID_SHORT_NAME;
    extern const std::string OWNERID_OID_LONG_NAME;
    struct PKCS7Attr;
    class SignerConfig;
    class ISigner;
    class BCSignedDataGenerator : public SignedDataGenerator {
    public:
        /**
        * Generate signature data with specific content and sign configuration.
        *
        * @param content      unsigned file digest content.
        * @param signerConfig sign configurations.
        * @ret signed data.
        * @return 0:success <0:error
        */
        int GenerateSignedData(const std::string& content, SignerConfig* signerConfig, std::string& ret)override;
        void SetOwnerId(const std::string& ownerID);
        static int GetSigAlg(SignerConfig* signerConfig, std::string& sigAlg);
    private:
        int PackageSignedData(const std::string& content, std::shared_ptr<ISigner> signer,
            STACK_OF(X509_CRL)* crls, const std::string& sigAlg, std::string& ret);
        //@return 0(NID_undef) >0: success(new NID)
        static int CreateNIDFromOID(const std::string& oid, const std::string& shortName,
            const std::string& longName);
        //@return 0:success <0 :error
        int AddOwnerID(std::vector<PKCS7Attr>& attrs, const std::string& ownerID);
    private:
        std::string ownerID;
    };
}
#endif //SIGNERTOOLS_BC_SIGNEDDATA_GENERATOR_H