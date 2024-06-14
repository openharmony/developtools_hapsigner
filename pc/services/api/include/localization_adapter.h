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

#ifndef SIGNATRUETOOLS_LOCALIIZATION_ADAPTER_H
#define SIGNATRUETOOLS_LOCALIIZATION_ADAPTER_H

#include <memory>
#include <string>

#include "openssl/ssl.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "options.h"
#include "key_store_helper.h"
#include "cert_dn_utils.h"
#include "signature_tools_log.h"
#include "verify_hap_openssl_utils.h"
namespace OHOS {
namespace SignatureTools {
class LocalizationAdapter {
public:
    LocalizationAdapter() = default;
    LocalizationAdapter(Options* options);
    ~LocalizationAdapter() = default;

    int IsAliasExist(const std::string& alias);
    EVP_PKEY* GetAliasKey(bool autoCreate);
    void ResetPwd();
    void SetIssuerKeyStoreFile(bool issuerKeyStoreFile);
    int GetKeyPair(bool autoCreate, EVP_PKEY** keyPair);
    STACK_OF(X509*) GetSignCertChain();
    EVP_PKEY* GetIssureKeyByAlias();
    bool IsOutFormChain();
    X509* GetSubCaCertFile();
    int IssuerKeyStoreFile(EVP_PKEY** keyPair, bool autoCreate);
    int KeyStoreFile(EVP_PKEY** keyPair, bool autoCreate);
    const std::string GetSignAlg() const;
    X509* GetCaCertFile();
    std::vector<X509*> GetCertsFromFile(std::string& certPath, const std::string& logTitle);
    const std::string GetOutFile();
    const std::string GetInFile();
    Options* options;
    std::unique_ptr<KeyStoreHelper> keyStoreHelper;
    bool IsRemoteSigner();
    Options* GetOptions();
    void AppAndProfileAssetsRealse(std::initializer_list<EVP_PKEY*> keys,
                                   std::initializer_list<X509_REQ*> reqs,
                                   std::initializer_list<X509*> certs);
private:
    void ResetChars(char* chars);
    bool isIssuerKeyStoreFile;
    static constexpr int MIN_CERT_CHAIN_SIZE = 2;
    static constexpr int MAX_CERT_CHAIN_SIZE = 3;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_LOCALIIZATION_ADAPTER_H
