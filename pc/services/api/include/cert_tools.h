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
#ifndef SIGNERTOOLS_CERT_TOOLS_H
#define SIGNERTOOLS_CERT_TOOLS_H
#include "cert_dn_utils.h"
#include "openssl/x509v3.h"
#include "localization_adapter.h"
namespace OHOS {
    namespace SignatureTools {
        class LocalizationAdapter;
        class CertTools {
        public:
            CertTools() = default;
            ~CertTools() = default;
            /**
         * the method of generateRootCertificate
         */
            static  X509* GenerateRootCertificate(EVP_PKEY* keyPair, X509_REQ* certReq, Options* options);
            /**
         * the method of generateSubCertificate
         */
            static X509* GenerateSubCert(EVP_PKEY* keyPair, X509_REQ* certReq, Options* options);
            /**
        * the method of generategeneralCertificate
        */
            static X509* GenerateCert(EVP_PKEY* keyPair, X509_REQ* certReq, Options* options);
            /**
        
         * save certificate to file
         */
            static void SaveCertTofile(const std::string& filename, X509* cer);
            /**
         * generate csr
         */
            static X509_REQ* GenerateCsr(EVP_PKEY* evpPkey, std::string signAlgorithm, std::string subject);
            /**
         
         * sign in order for  subCert
         */
          
           static X509* SignCsrGenerateCert(X509_REQ* rootcsr, X509_REQ* subcsr,
               EVP_PKEY* keyPair, Options* options);
            static std::string CsrToString(X509_REQ* csr);
            /**
         * Generate app or profile certificate
         */
            static X509* GenerateEndCert(X509_REQ* csr, EVP_PKEY* issuerKeyPair,
                                         LocalizationAdapter& adapter,
                                         const char signCapacity[],
                                         int capacityLen,
                                         X509_NAME* issuerName);
            /**
         *    cert file
         */
            static X509* ReadfileToX509(const std::string& filename);

           

            static X509* SetBisicConstraintsPatchLen(Options* options, X509* cert);

            static X509* SetSubjectForCert(X509_REQ* certReq, X509* cert);
            static X509* SignForSubCert(X509* cert, X509_REQ* csr, X509_REQ* caReq,
                                        EVP_PKEY* ca_prikey, Options* options);
            static X509* SetExpandedInfExtOne(X509* cert, Options* options,
                                              std::string critical, X509_EXTENSION* ext);
            static X509* SetExpandedInfExtTwo(X509* cert, Options* options,
                                              std::string critical, X509_EXTENSION* ext);
            static X509* SetExpandedInfExtThree(X509* cert, Options* options,
                                                std::string critical, X509_EXTENSION* ext);
            static bool SetCertVersion(X509* cert, int versionNum);
            static bool SetCertSerialNum(X509* cert, long serialNum);
            static bool SetCertIssuerName(X509* cert, X509_NAME* issuer);
            static bool SetCertSubjectName(X509* cert, X509_REQ* subjectCsr);
            static bool SetCertValidityStartAndEnd(X509* cert, long vilidityStart, long vilidityEnd);
            static bool SetCertPublickKey(X509* cert, X509_REQ* subjectCsr);
            static bool SetBasicExt(X509* cert);
            static bool SetkeyUsageExt(X509* cert);
            static bool SetKeyUsageEndExt(X509* cert);
            static bool SetKeyIdentifierExt(X509* cert);
            static bool SetSignCapacityExt(X509* cert, const char signCapacity[], int capacityLen);
            static bool SignCert(X509* cert, EVP_PKEY* privateKey, std::string signAlg);
            static X509* SetExpandedInformation(X509* cert, Options* options);
            static X509* SetPubkeyAndSignCert(X509* cert, X509_REQ* issuercsr,
                                              X509_REQ* certReq, EVP_PKEY* keyPair, Options* options);
        };
    } // namespace SignatureTools
} // namespace OHOS
#endif
