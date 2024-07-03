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
#include "content_digest_algorithm.h"
namespace OHOS {
namespace SignatureTools {
const ContentDigestAlgorithm ContentDigestAlgorithm::SHA256("SHA-256", 256 / 8);
const ContentDigestAlgorithm ContentDigestAlgorithm::SHA384("SHA-384", 384 / 8);
const ContentDigestAlgorithm ContentDigestAlgorithm::SHA512("SHA-512", 512 / 8);

ContentDigestAlgorithm::ContentDigestAlgorithm()
    : digestAlgorithm(""),
    digestOutputByteSize(0)
{
}

ContentDigestAlgorithm::ContentDigestAlgorithm(const ContentDigestAlgorithm& other)
    : digestAlgorithm(other.digestAlgorithm),
    digestOutputByteSize(other.digestOutputByteSize)
{
}

ContentDigestAlgorithm& ContentDigestAlgorithm::operator=(const ContentDigestAlgorithm& other)
{
    if (this != &other) {
        digestAlgorithm = other.digestAlgorithm;
        digestOutputByteSize = other.digestOutputByteSize;
    }
    return *this;
}

ContentDigestAlgorithm::ContentDigestAlgorithm(const std::string& digestAlgorithm,
                                               const int digestOutputByteSize)
    : digestAlgorithm(digestAlgorithm), digestOutputByteSize(digestOutputByteSize)
{
}

std::string ContentDigestAlgorithm::GetDigestAlgorithm()
{
    return digestAlgorithm;
}

int ContentDigestAlgorithm::GetDigestOutputByteSize()
{
    return digestOutputByteSize;
}
} // namespace SignatureTools
} // namespace OHOS