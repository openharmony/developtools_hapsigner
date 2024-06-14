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
#include <iostream>

#include "signer_factory.h"
#include "localization_adapter.h"
#include "signer_config.h"

namespace OHOS {
namespace SignatureTools {
SignerConfig::SignerConfig() : options(nullptr),
    certificates(nullptr),
    x509CRLs(nullptr),
    signer(nullptr),
    compatibleVersion(0)
{
}

SignerConfig::~SignerConfig()
{
    if (!certificates) {
        sk_X509_pop_free(certificates, X509_free);
    }
}

Options* SignerConfig::GetOptions() const
{
    return options;
}

void SignerConfig::SetOptions(Options* options)
{
    this->options = options;
}

STACK_OF(X509)* SignerConfig::GetCertificates() const
{
    if (IsInputCertChainNotEmpty() || signer == nullptr) {
        return certificates;
    }
    return signer->GetCertificates();
}

void SignerConfig::SetCertificates(STACK_OF(X509)* _certificates)
{
    certificates = _certificates;
}

STACK_OF(X509_CRL)* SignerConfig::GetX509CRLs() const
{
    if (IsInputCertChainNotEmpty() || IsInputCrlNotEmpty() || signer == nullptr) {
        return x509CRLs;
    }
    return signer->GetCrls();
}

void SignerConfig::SetX509CRLs(STACK_OF(X509_CRL)* crls)
{
    this->x509CRLs = crls;
}

std::vector<SignatureAlgorithmHelper> SignerConfig::GetSignatureAlgorithms() const
{
    return signatureAlgorithms;
}

void SignerConfig::SetSignatureAlgorithms(const std::vector<SignatureAlgorithmHelper>& _signatureAlgorithms)
{
    this->signatureAlgorithms = _signatureAlgorithms;
}

const std::map<std::string, std::string>& SignerConfig::GetSignParamMap() const
{
    return signParamMap;
}

void SignerConfig::FillParameters(const std::map<std::string, std::string>& params)
{
    this->signParamMap = params;
}

std::shared_ptr<Signer> SignerConfig::GetSigner()
{
    if (signer == nullptr) {
        SignerFactory factory;
        LocalizationAdapter adapter(options);
        signer = factory.GetSigner(adapter);
    }
    return signer;
}

int SignerConfig::GetCompatibleVersion() const
{
    return compatibleVersion;
}

void SignerConfig::SetCompatibleVersion(int _compatibleVersion)
{
    this->compatibleVersion = _compatibleVersion;
}

bool SignerConfig::IsInputCertChainNotEmpty() const
{
    return certificates != nullptr;
}

bool SignerConfig::IsInputCrlNotEmpty() const
{
    return x509CRLs != nullptr;
}
} // namespace SignatureTools
} // namespace OHOS