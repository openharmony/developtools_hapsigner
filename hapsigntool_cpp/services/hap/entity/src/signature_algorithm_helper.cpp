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
#include "signature_algorithm_helper.h"

namespace OHOS {
namespace SignatureTools {
SignatureAlgorithmHelper::SignatureAlgorithmHelper() : id(SignatureAlgorithmId::ECDSA_WITH_SHA256),
    keyAlgorithm(""),
    contentDigestAlgorithm(ContentDigestAlgorithm::SHA256),
    signatureAlgAndParams("", nullptr)
{
}

SignatureAlgorithmHelper::SignatureAlgorithmHelper(const SignatureAlgorithmHelper& other) : id(other.id),
    keyAlgorithm(other.keyAlgorithm),
    contentDigestAlgorithm(other.contentDigestAlgorithm),
    signatureAlgAndParams(other.signatureAlgAndParams.first, nullptr)
{
}

SignatureAlgorithmHelper& SignatureAlgorithmHelper::operator=(const SignatureAlgorithmHelper& other)
{
    if (this != &other) {
        id = other.id;
        keyAlgorithm = other.keyAlgorithm;
        contentDigestAlgorithm = other.contentDigestAlgorithm;
        signatureAlgAndParams.first = other.signatureAlgAndParams.first;
        signatureAlgAndParams.second = other.signatureAlgAndParams.second;
    }
    return *this;
}

SignatureAlgorithmHelper::~SignatureAlgorithmHelper()
{
}

const SignatureAlgorithmHelper* SignatureAlgorithmHelper::FindById(SignatureAlgorithmId id)
{
    if (id == SignatureAlgorithmId::ECDSA_WITH_SHA256) return &ECDSA_WITH_SHA256_INSTANCE;
    if (id == SignatureAlgorithmId::ECDSA_WITH_SHA384) return &ECDSA_WITH_SHA384_INSTANCE;
    return nullptr;
}

SignatureAlgorithmHelper::SignatureAlgorithmHelper(SignatureAlgorithmId id_, std::string keyAlg_,
                                                   ContentDigestAlgorithm digestAlg_,
                                                   std::pair<std::string, void*> sigParams_)
    : id(id_), keyAlgorithm(keyAlg_), contentDigestAlgorithm(digestAlg_), signatureAlgAndParams(sigParams_)
{
}

const SignatureAlgorithmHelper SignatureAlgorithmHelper::ECDSA_WITH_SHA256_INSTANCE{
    SignatureAlgorithmId::ECDSA_WITH_SHA256, "EC", ContentDigestAlgorithm::SHA256,
    {"SHA256withECDSA", nullptr} };

const SignatureAlgorithmHelper SignatureAlgorithmHelper::ECDSA_WITH_SHA384_INSTANCE{
    SignatureAlgorithmId::ECDSA_WITH_SHA384, "EC", ContentDigestAlgorithm::SHA384,
    {"SHA384withECDSA", nullptr} };
} // namespace SignatureTools
} // namespace OHOS