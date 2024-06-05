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

#ifndef SIGNERTOOLS_PARAM_PROCESS_UTIL_H
#define SIGNERTOOLS_PARAM_PROCESS_UTIL_H

#include <unordered_set>
#include <vector>
#include <string>
#include "verify_openssl_utils.h"
#include "signature_algorithm.h"
#include "param_constants.h"
namespace OHOS {
    namespace SignatureTools {
        class ParamProcessUtil {
        public:
            static std::unordered_set<std::string> initParamField(const std::vector<std::string>& paramFields);
            static bool getSignatureAlgorithm(const std::string& signatureAlgorithm, SignatureAlgorithmClass& out);
            static std::string convertSigAlgToDigAlg(const std::string& signatureAlgorithm);
        private:
            ParamProcessUtil() = default; // 构造函数私有化，防止实例化
        };
    }
}
#endif