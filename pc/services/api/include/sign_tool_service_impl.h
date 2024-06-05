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
#ifndef SIGNERTOOLS_SIGNTOOLSERVICELMPL_H
#define SIGNERTOOLS_SIGNTOOLSERVICELMPL_H
#include "options.h"
#include "file_utils.h"
#include "cert_tools.h"
#include "localization_adapter.h"
#include "signature_tools_log.h"
#include "service_api.h"
namespace OHOS {
    namespace SignatureTools {
        class SignToolServiceImpl : public ServiceApi {
        public:
            SignToolServiceImpl() = default;
            virtual ~SignToolServiceImpl() = default;
            //generate CA certificate
            bool GenerateCA(Options* options)override;
            bool GenerateRootCertToFile(Options* options, EVP_PKEY* rootKey, X509* cert);
            bool GenerateSubCertToFile(Options* options, EVP_PKEY* rootKey, X509* cert);
            bool HandleIssuerKeyAliasEmpty(std::string iksFile, std::unique_ptr<FileUtils>* sutils, Options* options);
            bool HandleIsserKeyAliasNotEmpty(Options* options);
            bool GenerateCert(Options* options)override;
            //Generate keyStore.
            bool GenerateKeyStore(Options* options)override;
            bool GenerateCsr(Options* options)override;
            bool OutputString(std::string content, std::string file);
            //Generate App Cert Interface
            bool GenerateAppCert(Options* option)override;
            //Generate Profile Cert Interface
            bool GenerateProfileCert(Options* options)override;
            //Get CaCert And SubCaCert And (App,Profile)Cert to OutPut File Interface
            bool GetAndOutPutCert(LocalizationAdapter& adapter, X509* cert);
            bool SignProfile(Options* options)override;
            bool SignHap(Options* options)override;
            /**
             * Verify profile.
             *
             * @param options options
             * @return Verify or not
             */
            bool VerifyProfile(Options* options)override;
            //CertChain OutPut Interface
            bool OutPutCertChain(std::vector<X509*>& certs, const std::string& outPutPath);
            //Cert OutPut Interface
            bool OutPutCert(X509* certs, const std::string& outPutPath);
            /**
         * Get provision content.
         * @param input input provision profile
         * @ret file data
         * @return 0:success <0:error
         */
            static int GetProvisionContent(const std::string& input, std::string& ret);
            //print X509 cert to CMD
            bool PrintX509FromMemory(X509* cert);
            bool VerifyHap(Options* option)override;
    
            bool X509CertVerify(X509* cert, EVP_PKEY* privateKey);
            X509_REQ* GetCsr(EVP_PKEY* keyPair, std::string signAlg, std::string subject);
        };
    }
}
#endif