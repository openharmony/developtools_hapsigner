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
#ifndef HAP_VERIFY_H
#define HAP_VERIFY_H
#include <string>
#include "export_define.h"
#include "hap_verify_result.h"
#include "signature_info.h"
#include "options.h"
namespace OHOS {
    namespace SignatureTools {
        DLL_EXPORT int32_t HapVerify(const std::string& filePath, HapVerifyResult& hapVerifyResult, Options* options);
        DLL_EXPORT int32_t ParseHapProfile(const std::string& filePath, HapVerifyResult& hapVerifyV1Result,
            const std::string& outPath);
        DLL_EXPORT int32_t ParseHapSignatureInfo(const std::string& filePath, SignatureInfo& hapSignInfo);
    } // namespace SignatureTools
} // namespace OHOS
#endif // HAP_VERIFY_H
