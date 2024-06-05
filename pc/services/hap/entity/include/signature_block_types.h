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

#ifndef SIGNERTOOLS_SIGNATURE_BLOCK_TYPES_H
#define SIGNERTOOLS_SIGNATURE_BLOCK_TYPES_H
#include <string>

namespace OHOS {
namespace SignatureTools {
class SignatureBlockTypes
{
public:
    /**
     * type-value of hap signature block
     */
    static const char SIGNATURE_BLOCK = 0;

    /**
     * type-value of unsigned profile
     */
    static const char PROFILE_NOSIGNED_BLOCK = 1;

    /**
     * type-value of signed profile
     */
    static const char PROFILE_SIGNED_BLOCK = 2;

    /**
     * type-value of key rotation block
     */
    static const char KEY_ROTATION_BLOCK = 3;

public:
    static char GetProfileBlockTypes(const std::string &isSigned);
};

}
} // namespace OHOS

#endif