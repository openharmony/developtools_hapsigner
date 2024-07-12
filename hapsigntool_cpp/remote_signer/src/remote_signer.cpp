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
#include <vector>
#include <algorithm>
#include "pkcs12_parser.h"
#include "remote_signer.h"

namespace OHOS {
namespace SignatureTools {
static EVP_PKEY* LoadPrivateKey(const std::string& keyStorePath, const std::string& keyAlias,
                                const std::string& keyStorePwd, const std::string& keyPwd)
{
    REMOTE_SIGNER_LOGI("keyStorePath: %s, keyAlias: %s, keyStorePwd: %s, keyPwd: %s",
                       keyStorePath.c_str(), keyAlias.c_str(), keyStorePath.c_str(), keyPwd.c_str());
    EVP_PKEY* pkey = NULL;
    PKCS12Parser parser(keyStorePath);
    if (parser.Parse(keyAlias.c_str(), keyStorePwd.c_str(), keyPwd.c_str(), &pkey, NULL, NULL) != 1) {
        REMOTE_SIGNER_LOGE("parse error\n");
        return NULL;
    }
    return pkey;
}

static STACK_OF(X509)* ReadCerts(const std::string& path)
{
    X509* cert = NULL;
    BIO* in = NULL;
    STACK_OF(X509)* certs = NULL;
    certs = sk_X509_new(NULL);
    if (certs == NULL) {
        goto err;
    }
    in = BIO_new_file(path.c_str(), "rb");
    if (in == NULL) {
        goto err;
    }
    while ((cert = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
        sk_X509_push(certs, cert);
    }
    BIO_free(in);
    return certs;
err:
    BIO_free(in);
    sk_X509_pop_free(certs, X509_free);
    return NULL;
}

RemoteSigner::RemoteSigner(std::string _keyAlias, std::string _signServer, std::string _onlineAuthMode,
                           std::string _username, std::string _userPwd)
    : keyAlias(_keyAlias), signServer(_signServer), onlineAuthMode(_onlineAuthMode), username(_username),
    userPwd(_userPwd)
{
}

RemoteSigner::~RemoteSigner()
{
    REMOTE_SIGNER_LOGI("RemoteSigner::~RemoteSigner()\n");
}

std::string RemoteSigner::GetSignature(const std::string &data, const std::string &signAlg) const
{
    REMOTE_SIGNER_LOGI("RemoteSigner::GetSignature()\n");
    EVP_MD_CTX* md_ctx = NULL;
    EVP_PKEY_CTX* pkey_ctx = NULL;
    unsigned char* sigret = NULL;
    const EVP_MD* md = NULL;
    size_t siglen;
    std::string ret;
    if (signAlg == "SHA256withECDSA") {
        md = EVP_sha256();
    } else if (signAlg == "SHA384withECDSA") {
        md = EVP_sha384();
    } else {
        REMOTE_SIGNER_LOGE("unsupport sigAlg\n");
        return ret;
    }
    md_ctx = EVP_MD_CTX_new();

    /* keystoreFile: OpenHarmony.p12 (onlineAuthMode)
    keyAlias: oh-app1-key-v1 (keyAlias)
    keystorePwd: 123456 (username)
    keyPwd: 123456 (userPwd) */
    EVP_PKEY* pkey = LoadPrivateKey(onlineAuthMode, keyAlias, username, userPwd);
    if(!pkey) {
        REMOTE_SIGNER_LOGE("LoadPrivateKey error: %s\n",onlineAuthMode.c_str());
        goto err;
    }
    if (EVP_DigestSignInit(md_ctx, &pkey_ctx, md, NULL, pkey) < 0) {
        REMOTE_SIGNER_LOGE("sign init error\n");
        goto err;
    }
    if (EVP_DigestSignUpdate(md_ctx, data.data(), data.size()) != 1) {
        REMOTE_SIGNER_LOGE("update error!\n");
        goto err;
    }
    if (EVP_DigestSignFinal(md_ctx, NULL, &siglen) <= 0) {
        REMOTE_SIGNER_LOGE("EVP_DigestSignFinal error\n");
        goto err;
    }
    sigret = reinterpret_cast<unsigned char*>(OPENSSL_malloc(siglen));
    if (EVP_DigestSignFinal(md_ctx, sigret, &siglen) != 1) {
        REMOTE_SIGNER_LOGE("sign final error\n");
        goto err;
    }
    ret.assign(reinterpret_cast<const char*>(sigret), siglen);
err:
    OPENSSL_free(sigret);
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

STACK_OF(X509_CRL)* RemoteSigner::GetCrls() const
{
    REMOTE_SIGNER_LOGI("RomoteSigner::GetCrls()\n");
    return nullptr;
}

bool X509NameCompare(const X509* cert, const X509* issuerCert)
{
    if (cert == nullptr || issuerCert == nullptr) {
        return false;
    }
    X509_NAME* aName = X509_get_issuer_name(cert);
    X509_NAME* bName = X509_get_subject_name(issuerCert);
    if (X509_NAME_cmp(aName, bName) != 0) {
        return false;
    }
    return true;
}

void ReverseX509Stack(STACK_OF(X509)* certs)
{
    if (certs == NULL) {
        return;
    }
    std::vector<X509*> certChain;
    for (int i = 0; i < sk_X509_num(certs); i++) {
        certChain.push_back(sk_X509_value(certs, i));
    }
    std::reverse(certChain.begin(), certChain.end());
    while (sk_X509_num(certs)) {
        sk_X509_pop(certs);
    }
    for (int i = 0; i < static_cast<int>(certChain.size()); i++) {
        sk_X509_push(certs, certChain[i]);
    }
}

STACK_OF(X509)* RemoteSigner::GetCertificates() const
{
    REMOTE_SIGNER_LOGI("RemoteSigner::GetCertificates()\n");
    STACK_OF(X509)* ret = ReadCerts(signServer);  // appCertFile: app-release1.pem (signServer)
    // In C++, the certificate chain order is positive, java is reverse,
    // by checking whether the first certificate is self-signed to order is positive
    if (ret == NULL || sk_X509_num(ret) == 0) {
        return nullptr;
    }
    if (X509NameCompare(sk_X509_value(ret, 0), sk_X509_value(ret, 0)) == true) {
        ReverseX509Stack(ret);
    }
    return ret;
}

} // SignatureTools
} // OHOS

OHOS::SignatureTools::Signer* Create(RemoteSignerParamType keyAlias, RemoteSignerParamType signServer,
    RemoteSignerParamType onlineAuthMode, RemoteSignerParamType username, RemoteSignerParamType userPwd)
{
    std::string _keyAlias(keyAlias.data, keyAlias.len);
    std::string _server(signServer.data, signServer.len);
    std::string _online(onlineAuthMode.data, onlineAuthMode.len);
    std::string _username(username.data, username.len);
    std::string _userPwd(userPwd.data, userPwd.len);
    return new OHOS::SignatureTools::RemoteSigner(_keyAlias, _server, _online, _username, _userPwd);
}