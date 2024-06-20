/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#ifndef SIGNATRUETOOLS_KEYSTOREHELPER_H
#define SIGNATRUETOOLS_KEYSTOREHELPER_H
#include <string>
#include "openssl/ssl.h"
#include "openssl/pem.h"
#include "openssl/evp.h"
#include "openssl/pkcs12.h"
#include "openssl/pkcs7.h"
#include "signature_tools_log.h"
#include "verify_hap_openssl_utils.h"

namespace OHOS {
namespace SignatureTools {
class KeyStoreHelper {
public:
    KeyStoreHelper();
    ~KeyStoreHelper() = default;
    int Store(EVP_PKEY* evpPkey, std::string& keyStorePath, char* storePwd,
              std::string alias, char* keyPwd);

    int ReadStore(std::string keyStorePath, char* storePwd, const std::string& alias,
                  char* keyPwd, EVP_PKEY** evpPkey);

    bool IsKeyStoreFileExist(std::string& keyStorePath);

    int GetPublicKey(PKCS7* safe, const char* alias, char* pass, int passlen, EVP_PKEY** publickey);
    int GetPrivateKey(PKCS7* safe, const char* alias, char* pass, int passlen, EVP_PKEY** keyPiar);
    int SetCertPkcs12(X509* cert, PKCS12_SAFEBAG* bag, STACK_OF(PKCS12_SAFEBAG)* bags,
                      unsigned char* keyid, unsigned int keyidlen, STACK_OF(X509)* ca,
                      const char* name, STACK_OF(PKCS7)** safes,
                      int nid_cert, int iter, const char* pass);

    int SetPkeyPkcs12(EVP_PKEY* pkey, PKCS12_SAFEBAG* bag, STACK_OF(PKCS12_SAFEBAG)* bags,
                      const char* name, STACK_OF(PKCS7)** safes, int iter, const char* keyPass,
                      int keytype, int nid_key, unsigned char* keyid, unsigned int keyidlen);

    bool InitX509(X509& cert, EVP_PKEY& evpPkey);

    void SetNidMac(int& nid_key, int& iter, int& mac_iter);

    EVP_PKEY* GenerateKeyPair(const std::string& algorithm, int keySize);

    PKCS12* Pkcs12Create(const char* pass, const char* keyPass,
                         const char* name, EVP_PKEY* pkey, X509* cert,
                         STACK_OF(X509)* ca, int nid_key, int nid_cert, int iter,
                         int mac_iter, int keytype, STACK_OF(PKCS7)** safes);

    int CopyBagAttr(PKCS12_SAFEBAG* bag, EVP_PKEY* pkey, int nid);

    int FindFriendlyName(PKCS12* p12, const char* alias, char* keyPass, char* pass, EVP_PKEY** keyPiar);

    int ParseBag(PKCS12_SAFEBAG* bag, const char* pass, int passlen,
                 EVP_PKEY** pkey, STACK_OF(X509)* ocerts);

    int ParseBags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* pass,
                  int passlen, EVP_PKEY** pkey, STACK_OF(X509)* ocerts);

    bool X509AliasSet1(int len, X509* x509, unsigned char* data);
    int Pkcs12Parse(PKCS12* p12, const char* pass);
    int CreatePKCS12(PKCS12** p12, const char* charsStorePath, char* storePwd,
                     char* keyPwd, const char* charsAlias, EVP_PKEY* evpPkey, X509* cert);

    bool GetPassWordStatus();
    void SetPassWordStatus(bool status);

private:
    void KeyPairFree(EC_GROUP* group, EC_KEY* pkey, const std::string& Message);
    void KeyPairFree(BIGNUM* bnSerial, X509_NAME* issuerName, X509_NAME* subjectName,
                     ASN1_INTEGER* ai, const std::string& Message);
    void KeyPairFree(X509* cert, PKCS12* p12, BIO* bioOut, const std::string& Message);
    void KeyPairFree(EVP_PKEY* keyPiar, STACK_OF(X509)* ocerts,
                     STACK_OF(PKCS12_SAFEBAG)* bags, char* name);
    void KeyPairFree(STACK_OF(PKCS7)* safes, EVP_PKEY* publickey);
    void KeyPairFree(STACK_OF(PKCS12_SAFEBAG)* bags, PKCS8_PRIV_KEY_INFO* p8, char* name, const std::string& Message);
    void ResetKeyStatusvariable();
    void ResePwdLenvariable();

private:
    static constexpr int SECONDS = 60;
    static constexpr int MINUTES = 60;
    static constexpr int HOURS = 24;
    static constexpr int DAYS = 30;
    static constexpr int NID_PBE_CBC = 149;
    static constexpr int NID_TRIPLEDES_CBC = 146;
    static constexpr int PATH_SIZE = 100;

    bool passWordStatus;
    int keyStorePwdLen;
    int keyPairPwdLen;
    int publicKeyStatus;
    int privateKeyStatus;
};
} // namespace SignatureTools
} // namespace OHOS
#endif
