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
#ifndef SIGNATURETOOLS_HASH_UTILS_H
#define SIGNATURETOOLS_HASH_UTILS_H
#include <string>
#include <vector>

namespace OHOS {
namespace SignatureTools {
enum class HashAlgs
{
    /**
     * None
     */
    USE_NONE = 0,

    /**
     * The MD2 message digest.
     */
    USE_MD2 = 1,

    /**
     * The MD4 message digest.
     */
    USE_MD4 = 2,

    /**
     * The MD5 message digest.
     */
    USE_MD5 = 3,

    /**
     * The SSH-1 message digest.
     */
    USE_SHA1 = 4,

    /**
     * The SSH-224 message digest.
     */
    USE_SHA224 = 5,

    /**
     * The SSH-256 message digest.
     */
    USE_SHA256 = 6,

    /**
     * The SSH-384 message digest.
     */
    USE_SHA384 = 7,

    /**
     * The SSH-512 message digest.
     */
    USE_SHA512 = 8,

    /**
     * The RIPEMD-160 message digest.
     */
    USE_RIPEMD160 = 9,
};

class HashUtils 
{
public:
    static int GetHashAlgsId(const std::string& algMethod);
    static std::vector<signed char> GetFileDigest(const std::string& inputFile, const std::string& algName);
    static std::string GetHashAlgName(int algId);
    static std::vector<signed char> GetDigestFromBytes(const std::vector<int8_t>& fileBytes, int64_t length,
        const std::string& algName);

private:
    static std::vector<signed char> GetByteDigest(const std::string& str, int count, 
        const std::string& algMethod);

private:
    static const int HASH_LEN = 4096;
};

}
} // namespace OHOS
#endif