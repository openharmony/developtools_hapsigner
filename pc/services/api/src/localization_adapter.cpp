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
#include "localization_adapter.h"
#include <string>
#include <cstring>
using namespace OHOS::SignatureTools;
LocalizationAdapter::LocalizationAdapter(Options* options)
{
    this->options = options;
    this->keyStoreHelper = std::make_unique<KeyStoreHelper>();
    this->isIssuerKeyStoreFile = false;
}
int LocalizationAdapter::IsExist(std::string alias)
{
    std::string keyStoreFile = this->options->GetString(Options::KEY_STORE_FILE);
    if (!this->keyStoreHelper->GetFileStatus(keyStoreFile))
        return RET_FAILED;

    EVP_PKEY* keyPair = nullptr;
    char* keyStoreRight = this->options->GetChars(Options::KEY_STORE_RIGHTS);
    char* keyPwd = this->options->GetChars(Options::KEY_RIGHTS);
    int status = this->keyStoreHelper->ReadStore(keyStoreFile, keyStoreRight, alias, keyPwd, &keyPair);
    EVP_PKEY_free(keyPair);
    if (status == RET_OK) {
        return RET_OK;
    } else if (status == RET_PASS_ERROR) {
        return RET_PASS_ERROR;
    }
    return RET_FAILED;
}
void LocalizationAdapter::ResetPwd()
{
    char* keyRights = this->options->GetChars(Options::KEY_RIGHTS);
    if (keyRights != nullptr) {
        ResetChars(keyRights);
    }
    char* keyStoreRights = this->options->GetChars(Options::KEY_STORE_RIGHTS);
    if (keyStoreRights != nullptr) {
        ResetChars(keyStoreRights);
    }
    char* issuerKeyRights = this->options->GetChars(Options::ISSUER_KEY_RIGHTS);
    if (issuerKeyRights != nullptr) {
        ResetChars(issuerKeyRights);
    }
    char* issuerKeyStoreRights = this->options->GetChars(Options::ISSUER_KEY_STORE_RIGHTS);
    if (issuerKeyStoreRights != nullptr) {
        ResetChars(issuerKeyStoreRights);
    }
}
void LocalizationAdapter::ResetChars(char* chars)
{
    if (chars == NULL)
        return;
    for (size_t i = 0; i < strlen(chars); i++) {
        chars[i] = 0;
    }
}
EVP_PKEY* LocalizationAdapter::GetAliasKey(bool autoCreate)
{
    return this->GetKeyPair(autoCreate);
}
/********************************************************************************
*Explain
*
* Author: YinJiaRui
* time:2024/04/17
*
* Fun performance: Generate a key pair (If the key alias exists, find it from
        the key store. If it does not exist, create and save it to a p12 file)
* autoCreate: Whether automatically generated (true/false)
* return: Return EVP_PKEY pointer on success, NULL on failure
*********************************************************************************/
EVP_PKEY* LocalizationAdapter::GetKeyPair(bool autoCreate)
{
    if (this->keyStoreHelper == nullptr) {
        this->keyStoreHelper = std::make_unique<KeyStoreHelper>();
    }
    EVP_PKEY* keyPair = nullptr;
    std::string keyStorePath;
    if (this->isIssuerKeyStoreFile) {
        keyPair = this->IssuerKeyStoreFile(keyPair, autoCreate);
    } else {
        keyStorePath = this->options->GetString(Options::KEY_STORE_FILE);
        char* keyStoreRights = this->options->GetChars(Options::KEY_STORE_RIGHTS);
        char* keyPwd = this->options->GetChars(Options::KEY_RIGHTS);
        std::string keyAlias = this->options->GetString(Options::KEY_ALIAS);
        bool fileStatus = this->keyStoreHelper->GetFileStatus(keyStorePath);
        if (fileStatus) {
            int status = this->keyStoreHelper->ReadStore(keyStorePath, keyStoreRights, keyAlias, keyPwd, &keyPair);
            if (status == RET_OK) {
                return keyPair;
            } else if (status == RET_PASS_ERROR) {
                autoCreate = false;
            }
            keyPair = nullptr;
        }
        if (autoCreate) {
            std::string keyAlg = this->options->GetString(Options::KEY_ALG);
            int keySize = this->options->GetInt(Options::KEY_SIZE);
            keyPair = this->keyStoreHelper->GenerateKeyPair(keyAlg, keySize);
            char* keyStoreRights = this->options->GetChars(Options::KEY_STORE_RIGHTS);
            char* keyPwd = this->options->GetChars(Options::KEY_RIGHTS);
            std::string keyAlias = this->options->GetString(Options::KEY_ALIAS);
            if (keyAlias.empty()) {
                SIGNATURE_TOOLS_LOGI("keyAlias is nullptr!");
                return nullptr;
            }
            keyPair = this->keyStoreHelper->Store(keyPair, keyStorePath, keyStoreRights, keyAlias, keyPwd);
        }
    }
    this->isIssuerKeyStoreFile = false;
    return keyPair;
}

EVP_PKEY* LocalizationAdapter::IssuerKeyStoreFile(EVP_PKEY* keyPair, bool autoCreate)
{
    std::string keyStorePathIssuer = this->options->GetString(Options::ISSUER_KEY_STORE_FILE);
    std::string keyStorePath = this->options->GetString(Options::KEY_STORE_FILE);

    char* issuerKeyStoreRights = this->options->GetChars(Options::ISSUER_KEY_STORE_RIGHTS);
    char* issuerKeyPwd = this->options->GetChars(Options::ISSUER_KEY_RIGHTS);
    char* keyStoreRights = this->options->GetChars(Options::KEY_STORE_RIGHTS);
    std::string issuerKeyAlias = this->options->GetString(Options::ISSUER_KEY_ALIAS);

    bool fileStatus = this->keyStoreHelper->GetFileStatus(keyStorePathIssuer);
    if (fileStatus) {
        int status = this->keyStoreHelper->ReadStore(keyStorePathIssuer, issuerKeyStoreRights,
            issuerKeyAlias, issuerKeyPwd, &keyPair);
        if (status == RET_OK) {
            return keyPair;
        } else if (status == RET_PASS_ERROR) {
            autoCreate = false;
        }
        keyPair = nullptr;
    }
    
    fileStatus = this->keyStoreHelper->GetFileStatus(keyStorePath);
    if (fileStatus) {
        int status = this->keyStoreHelper->ReadStore(keyStorePath, keyStoreRights, issuerKeyAlias,
            issuerKeyPwd, &keyPair);
        if (status == RET_OK) {
            return keyPair;
        } else if (status == RET_PASS_ERROR) {
            autoCreate = false;
        }
        keyPair = nullptr;
    }
    if (autoCreate) {
        std::string keyAlg = this->options->GetString(Options::KEY_ALG);
        int keySize = this->options->GetInt(Options::KEY_SIZE);
        keyPair = this->keyStoreHelper->GenerateKeyPair(keyAlg, keySize);
        if (keyStorePathIssuer.empty()) {
            keyPair = this->keyStoreHelper->Store(keyPair, keyStorePath, keyStoreRights, issuerKeyAlias, issuerKeyPwd);
        } else {
            keyPair = this->keyStoreHelper->Store(keyPair, keyStorePathIssuer, issuerKeyStoreRights,
                issuerKeyAlias, issuerKeyPwd);
        }
    }
    return keyPair;
}

void LocalizationAdapter::SetIssuerKeyStoreFile(bool issuerKeyStoreFile)
{
    this->isIssuerKeyStoreFile = issuerKeyStoreFile;
}
STACK_OF(X509)* LocalizationAdapter::GetSignCertChain()
{
    std::string certPath = options->GetString(Options::PROFILE_CERT_FILE);
    if (certPath.empty()) {
        certPath = options->GetString(Options::APP_CERT_FILE);
    }
    STACK_OF(X509)* certificates = sk_X509_new(NULL);
    if (certificates == NULL) {
        SIGNATURE_TOOLS_LOGE("sk_X509_new failed\n");
        return  NULL;
    }
    std::vector<X509*> certs = this->GetCertsFromFile(certPath, Options::PROFILE_CERT_FILE);
    if (certs.size() == 0) {
        return NULL;
    }
    for (int i = 0; i < static_cast<int>(certs.size()); i++) {
        sk_X509_push(certificates, certs[i]);
    }
    if (sk_X509_num(certificates) < MIN_CERT_CHAIN_SIZE && sk_X509_num(certificates) > MAX_CERT_CHAIN_SIZE) {
        SIGNATURE_TOOLS_LOGE("Profile cert '%s' must a cert chain", certPath.c_str());
        sk_X509_free(certificates);
        return NULL;
    }
    return certificates;
}
/********************************************************************************
*Explain
*
* Author: yuanbin
* time:2024/04/19
*
* Funs performance:Get caCert and subCaCert for generate certchain(.pem).
* get issuerKey Pair to store in CertTools
*********************************************************************************/
EVP_PKEY* LocalizationAdapter::GetIssureKeyByAlias()
{
    return this->GetKeyPair(false);
}
bool LocalizationAdapter::IsOutFormChain()
{
    std::string checkStr = "certChain";
    std::string outForm = this->options->GetString(Options::OUT_FORM, checkStr);
    if (outForm.compare("certChain") == 0) {
        return true;
    } else {
        return false;
    }
}
X509* LocalizationAdapter::GetSubCaCertFile()
{
    std::string certPath = this->options->GetString(Options::SUB_CA_CERT_FILE);
    return GetCertsFromFile(certPath, Options::SUB_CA_CERT_FILE).at(0);
}
const std::string LocalizationAdapter::GetSignAlg() const
{
    return options->GetString(Options::SIGN_ALG);
}
X509* LocalizationAdapter::GetCaCertFile()
{
    std::string certPath = this->options->GetString(Options::CA_CERT_FILE);
    return GetCertsFromFile(certPath, Options::CA_CERT_FILE).at(0);
}
const std::string LocalizationAdapter::GetOutFile()
{
    return this->options->GetString(Options::OUT_FILE);
}
std::vector<X509*> LocalizationAdapter::GetCertsFromFile(std::string& certPath, const std::string& logTitle)
{
    HapVerifyOpensslUtils::GetOpensslErrorMessage();
    SIGNATURE_TOOLS_LOGD("outPutPath = %{public}s , logTitle = %{public}s", certPath.c_str(), logTitle.c_str());
    std::vector<X509*> certs;
    if (certPath.empty()) {
        SIGNATURE_TOOLS_LOGE("cert path not exist!");
        return certs;
    }
    //Read And Get Cert
    BIO* bio = BIO_new_file(certPath.c_str(), "rb");
    if (!bio) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("bio is nullptr!");
        BIO_free(bio);
        return certs;
    }
    X509* cert = nullptr;
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != nullptr) {
        certs.emplace_back(cert);
    }
    BIO_free(bio);
    return certs;
}
const std::string LocalizationAdapter::GetInFile()
{
    return this->options->GetString(Options::IN_FILE);
}

bool LocalizationAdapter::IsRemoteSigner()
{
    std::string defMode = "localSign";
    std::string destMode = "remoteSign";
    std::string mode = this->options->GetString(Options::MODE, defMode);
    return StringUtils::CaseCompare(mode, destMode);
}

Options* LocalizationAdapter::GetOptions()
{
    return options;
}
