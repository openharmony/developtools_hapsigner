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
#ifndef SIGNATURETOOLS_SIGNATUR_ALGORITHM_H
#define SIGNATURETOOLS_SIGNATUR_ALGORITHM_H
#include <string>
#include <utility> // for std::pair
#include "content_digest_algorithm.h" // 确保包含ContentDigestAlgorithm的定义
namespace OHOS {
    namespace SignatureTools {
        enum class SignatureAlgorithmId {
            RSA_PSS_WITH_SHA256 = 0x101,
            RSA_PSS_WITH_SHA384 = 0x102,
            RSA_PSS_WITH_SHA512 = 0x103,
            RSA_PKCS1_V1_5_WITH_SHA256 = 0x104,
            RSA_PKCS1_V1_5_WITH_SHA384 = 0x105,
            RSA_PKCS1_V1_5_WITH_SHA512 = 0x106,
            ECDSA_WITH_SHA256 = 0x201,
            ECDSA_WITH_SHA384 = 0x202,
            ECDSA_WITH_SHA512 = 0x203,
            DSA_WITH_SHA256 = 0x301,
            DSA_WITH_SHA384 = 0x302,
            DSA_WITH_SHA512 = 0x303
        };
        class SignatureAlgorithmClass {
        public:
            SignatureAlgorithmClass();
            SignatureAlgorithmClass(const SignatureAlgorithmClass& other);
            SignatureAlgorithmClass& operator=(const SignatureAlgorithmClass& other);
            ~SignatureAlgorithmClass();
            // 静态查找方法，通过ID找到对应的SignatureAlgorithm实例
            static const SignatureAlgorithmClass* FindById(SignatureAlgorithmId id);
            SignatureAlgorithmClass(SignatureAlgorithmId id_, std::string keyAlg_, ContentDigestAlgorithm digestAlg_,
                std::pair<std::string, void*> sigParams_);
            SignatureAlgorithmId id;
            std::string keyAlgorithm;
            ContentDigestAlgorithm contentDigestAlgorithm;
            std::pair<std::string, void*> signatureAlgAndParams;
            // 静态成员变量作为算法实例
            static const SignatureAlgorithmClass ECDSA_WITH_SHA256_INSTANCE;
            static const SignatureAlgorithmClass ECDSA_WITH_SHA384_INSTANCE;
        };
    }
}
#endif