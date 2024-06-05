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
#include "hap_verify.h"
#include <mutex>
#include "provision_verify.h"
#include "hap_verify_v2.h"
namespace OHOS {
    namespace SignatureTools {
        static std::mutex g_mtx;
        int32_t HapVerify(const std::string& filePath, HapVerifyResult& hapVerifyResult, Options* options)
        {
            HapVerifyV2 hapVerifyV2;
            return hapVerifyV2.Verify(filePath, hapVerifyResult, options);
        }
        int32_t ParseHapProfile(const std::string& filePath, HapVerifyResult& hapVerifyV1Result,
            const std::string& outPath)
        {
            HapVerifyV2 hapVerifyV2;
            return hapVerifyV2.ParseHapProfile(filePath, hapVerifyV1Result, outPath);
        }
        int32_t ParseHapSignatureInfo(const std::string& filePath, SignatureInfo& hapSignInfo)
        {
            HapVerifyV2 hapVerifyV2;
            return hapVerifyV2.ParseHapSignatureInfo(filePath, hapSignInfo);
        }
    } // namespace SignatureTools
} // namespace OHOS