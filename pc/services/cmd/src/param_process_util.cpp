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
#include "param_process_util.h"
#include "signature_tools_log.h"
namespace OHOS {
    namespace SignatureTools {
        std::unordered_set<std::string> ParamProcessUtil::initParamField(const std::vector<std::string>& paramFields)
        {
            return std::unordered_set<std::string>(paramFields.begin(), paramFields.end());
        }
        bool ParamProcessUtil::getSignatureAlgorithm(const std::string& signatureAlgorithm,
                                                     SignatureAlgorithmClass& out)
        {
            if (signatureAlgorithm == ParamConstants::HAP_SIG_ALGORITHM_SHA256_ECDSA) {
                out = SignatureAlgorithmClass::ECDSA_WITH_SHA256_INSTANCE;
                return true;
            } else if (signatureAlgorithm == ParamConstants::HAP_SIG_ALGORITHM_SHA384_ECDSA) {
                out = SignatureAlgorithmClass::ECDSA_WITH_SHA384_INSTANCE;
                return true;
            } else {
                SIGNATURE_TOOLS_LOGE("get Signature Algorithm failed not support %s", signatureAlgorithm.c_str());
                return false;
            }
            return true;
        }

        std::string ParamProcessUtil::convertSigAlgToDigAlg(const std::string& signatureAlgorithm)
        {
            if (signatureAlgorithm == ParamConstants::HAP_SIG_SCHEME_V256_DIGEST_ALGORITHM) {
                return ParamConstants::HAP_SIG_ALGORITHM_SHA256_ECDSA;
            } else if (signatureAlgorithm == ParamConstants::HAP_SIG_SCHEME_V384_DIGEST_ALGORITHM) {
                return ParamConstants::HAP_SIG_ALGORITHM_SHA384_ECDSA;
            } else if (signatureAlgorithm == ParamConstants::HAP_SIG_SCHEME_V512_DIGEST_ALGORITHM) {
                return ParamConstants::HAP_SIG_ALGORITHM_SHA512_ECDSA;
            } else {
                SIGNATURE_TOOLS_LOGE("convert sig alg to dig alg failed not support %s", signatureAlgorithm.c_str());
                return "";
            }
        }
    }
}