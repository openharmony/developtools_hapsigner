/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SIGNERTOOLS_BC_PKCS7_GENERATOR_GENERATOR_H
#define SIGNERTOOLS_BC_PKCS7_GENERATOR_GENERATOR_H
#include "pkcs7_generator.h"
#include "openssl/x509.h"
#include <string>
#include <memory>
namespace OHOS::SignatureTools {
    class SignerConfig;
    class ISigner;
    class BCPkcs7Generator : public Pkcs7Generator {
    public:
        /**
         * Generate PKCS#7 signed data with the specific content and signer config.
         *
         * @param content PKCS7 data, content of unsigned file digest.
         * @param signerConfig configurations of signer.
         * @ret PKCS7 signed data.
         * @return 0:success <0:error
         */
        virtual ~BCPkcs7Generator();
        int GenerateSignedData(const std::string& content, SignerConfig* signerConfig, std::string& ret) override;
    private:
        int PackagePKCS7(const std::string& content, std::shared_ptr<ISigner> signer, STACK_OF(X509_CRL)* crls,
            const std::string& sigAlg, std::string& ret);
    };
}
#endif //SIGNERTOOLS_BC_PKCS7_GENERATOR_GENERATOR_H