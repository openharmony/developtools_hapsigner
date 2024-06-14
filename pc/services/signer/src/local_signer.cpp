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
#include <cassert>

#include "signature_tools_log.h"
#include "pkcs7_data.h"
#include "constant.h"
#include "local_signer.h"

namespace OHOS {
namespace SignatureTools {
/**
* Create local signer.
*
* @param keyPair   Private key to sign
* @param certificates Cert chain to sign
*/
LocalSigner::LocalSigner(EVP_PKEY* keyPair, STACK_OF(X509)* certificates) :keyPair(keyPair),
certificates(certificates)
{
    if (this->keyPair && this->certificates && sk_X509_num(this->certificates)) {
        PKCS7Data::SortX509Stack(this->certificates);
        assert(X509_check_private_key(sk_X509_value(this->certificates, 0), this->keyPair) == 1);
    }
}
LocalSigner::~LocalSigner()
{
    if (this->keyPair) {
        EVP_PKEY_free(this->keyPair);
        this->keyPair = NULL;
    }
    if (this->certificates) {
        sk_X509_pop_free(certificates, X509_free);
        this->certificates = NULL;
    }
}
STACK_OF(X509_CRL)* LocalSigner::GetCrls() const
{
    return NULL;
}
STACK_OF(X509)* LocalSigner::GetCertificates() const
{
    return this->certificates;
}
std::string LocalSigner::GetSignature(const std::string& data, const std::string& signAlg) const
{
    EVP_MD_CTX* md_ctx = NULL;
    EVP_PKEY_CTX* pkey_ctx = NULL;
    unsigned char* sigret = NULL;
    const EVP_MD* md = NULL;
    size_t siglen;
    std::string ret;

    if (signAlg == SIGN_ALG_SHA256) {
        md = EVP_sha256();
    } else if (signAlg == SIGN_ALG_SHA384) {
        md = EVP_sha384();
    } else {
        SIGNATURE_TOOLS_LOGE("unsupport sigAlg\n");
        return ret;
    }

    // 计算签名值
    if (!(md_ctx = EVP_MD_CTX_new()) ||
        (EVP_DigestSignInit(md_ctx, &pkey_ctx, md, NULL, this->keyPair) <= 0) ||
        (EVP_DigestSignUpdate(md_ctx, data.data(), data.size()) <= 0) ||
        (EVP_DigestSignFinal(md_ctx, NULL, &siglen) <= 0) ||
        !(sigret = reinterpret_cast<unsigned char*>(OPENSSL_malloc(siglen))) ||
        (EVP_DigestSignFinal(md_ctx, sigret, &siglen) <= 0)) {
        SIGNATURE_TOOLS_LOGE("digest sign failed\n");
        goto err;
    }
    ret.assign(reinterpret_cast<const char*>(sigret), siglen);
err:
    OPENSSL_free(sigret);
    EVP_MD_CTX_free(md_ctx);
    return ret;
}
} // namespace SignatureTools
} // namespace OHOS