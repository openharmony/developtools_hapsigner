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
#ifndef SIGNERTOOLS_KEYSTOREHELPER_H
#define SIGNERTOOLS_KEYSTOREHELPER_H
#include <string>
#include "openssl/ssl.h"
#include "openssl/pem.h"
#include "openssl/evp.h"
#include "openssl/pkcs12.h"
#include "openssl/pkcs7.h"
#include "signature_tools_log.h"
#include "verify_openssl_utils.h"

namespace OHOS {
    namespace SignatureTools {
        class KeyStoreHelper {
        public:
            KeyStoreHelper() = default;
            ~KeyStoreHelper() = default;
            EVP_PKEY* Store(EVP_PKEY* evpPkey, std::string keyStorePath, char* storePwd, std::string alias, char* keyPwd);
            int ReadStore(std::string keyStorePath, char* storePwd, std::string alias, char* keyPwd, EVP_PKEY** evpPkey);
            bool GetFileStatus(std::string keyStorePath);
            int GetPublicKey(PKCS7* safe, char* alias, char* pass, int passlen, EVP_PKEY** publickey);
            int GetPrivateKey(PKCS7* safe, char* alias, char* pass, int passlen, EVP_PKEY** keyPiar);
            void I2dPkcs12BioFree(EVP_PKEY* evpPkey, X509* cert, PKCS12* p12, BIO* bioOut);
            void BIONewFileFree(EVP_PKEY* evpPkey, X509* cert, PKCS12* p12);
            int SetCertPkcs12(X509* cert, PKCS12_SAFEBAG* bag, STACK_OF(PKCS12_SAFEBAG)* bags,
                                           unsigned char* keyid, unsigned int keyidlen, STACK_OF(X509)* ca,
                                           const char* name, STACK_OF(PKCS7)** safes,
                                           int nid_cert, int iter, const char* pass);

            int SetPkeyPkcs12(EVP_PKEY* pkey, PKCS12_SAFEBAG* bag, STACK_OF(PKCS12_SAFEBAG)* bags,
                              const char* name, STACK_OF(PKCS7)** safes, int iter, const char* keyPass,
                              int keytype, int nid_key, unsigned char* keyid, unsigned int keyidlen);

            /**
         * Initialize the X509 structure.
         */
            bool InitX509(X509& cert, EVP_PKEY& evpPkey);

            EVP_PKEY* CheckAlias(STACK_OF(X509)* ocerts, STACK_OF(PKCS12_SAFEBAG)* bags,
                                 PKCS12_SAFEBAG* bag, char* alias);
            void ReadStorefailFree(BIO* bioOut, PKCS12* p12, X509* cert);
            void SetNidMac(int& nid_key, int& iter, int& mac_iter);

            /**
         * string to char*.
         */
            void StringToChars(std::string& str, char* chars);
            /**
         * Creating a key pair.
         */
            EVP_PKEY* GenerateKeyPair(std::string algorithm, int keySize);

            PKCS12* OwnPKCS12_create(const char* pass, const char* keyPass, const char* name, EVP_PKEY* pkey, X509* cert,
                                     STACK_OF(X509)* ca, int nid_key, int nid_cert, int iter,
                                     int mac_iter, int keytype, STACK_OF(PKCS12_SAFEBAG)* bags, STACK_OF(PKCS7)* safes);

            int CopyBagAttr(PKCS12_SAFEBAG* bag, EVP_PKEY* pkey, int nid);

            int FindFriendlyName(PKCS12* p12, char* alias, char* keyPass, char* pass, EVP_PKEY** keyPiar);

            int ParseBag(PKCS12_SAFEBAG* bag, const char* pass, int passlen,
                         EVP_PKEY** pkey, STACK_OF(X509)* ocerts);

            int ParseBags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* pass,
                          int passlen, EVP_PKEY** pkey, STACK_OF(X509)* ocerts);

            bool X509AliasSet1(int len, X509* x509, unsigned char* data);
            int OwnPKCS12_parse(PKCS12* p12, const char* pass);
            PKCS12* createPKCS12(PKCS12* p12, char* charsStorePath, char* storePwd,
                                  char* keyPwd, char* charsAlias, EVP_PKEY* evpPkey, X509* cert);
        };
    } // namespace SignatureTools
} // namespace OHOS
#endif