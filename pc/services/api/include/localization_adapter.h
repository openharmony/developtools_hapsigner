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
#ifndef SIGNERTOOLS_LOCALIIZATION_ADAPTER_H
#define SIGNERTOOLS_LOCALIIZATION_ADAPTER_H
#include <memory>
#include <string>
#include "openssl/ssl.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "options.h"
#include "key_store_helper.h"
#include "cert_dn_utils.h"
#include "cert_tools.h"
#include "signature_tools_log.h"
#include "verify_openssl_utils.h"
namespace OHOS {
    namespace SignatureTools {
        class LocalizationAdapter {
        public:
            LocalizationAdapter() = default;
            LocalizationAdapter(Options* options);
            ~LocalizationAdapter() = default;
            /**
         * Check whether alias exists.If yes, a message is displayed.
         */
            int IsExist(std::string alias);
            /**
         * Generate key pair.
         */
            EVP_PKEY* GetAliasKey(bool autoCreate);
            /**
         * reset passwords.
         */
            void ResetPwd();
            void SetIssuerKeyStoreFile(bool issuerKeyStoreFile);
            EVP_PKEY* GetKeyPair(bool autoCreate);
            STACK_OF(X509*) GetSignCertChain();
            EVP_PKEY* GetIssureKeyByAlias();
            bool IsOutFormChain();
            X509* GetSubCaCertFile();
            EVP_PKEY* IssuerKeyStoreFile(EVP_PKEY* keyPair, bool autoCreate);
            /**
         * Get signature algorithm.
         *
         * @return signature algorithm.
         */
            const std::string GetSignAlg() const;
            X509* GetCaCertFile();
            std::vector<X509*> GetCertsFromFile(std::string& certPath, const std::string& logTitle);
            const std::string GetOutFile();
            const std::string GetInFile();

            /**
            * Check if it is a remote signature.
            *
            * @return result indicating whether the signer is a remote signer.
            */
            bool IsRemoteSigner();
            Options* GetOptions();

        private:
            void ResetChars(char* chars);
        public:
            Options* options;
            std::unique_ptr<KeyStoreHelper> keyStoreHelper;
        private:
            bool isIssuerKeyStoreFile;
            static constexpr int MIN_CERT_CHAIN_SIZE = 2;
            static constexpr int MAX_CERT_CHAIN_SIZE = 3;
        };
    } // namespace SignatureTools
} // namespace OHOS
#endif
