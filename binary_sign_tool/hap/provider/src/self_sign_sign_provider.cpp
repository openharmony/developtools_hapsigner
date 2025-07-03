/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "self_sign_sign_provider.h"
#include "params.h"
#include "sign_elf.h"

namespace OHOS {
namespace SignatureTools {
bool SelfSignSignProvider::SignElf(Options* options)
{
    if (!SignProvider::CheckParams(options)) {
        SIGNATURE_TOOLS_LOGE("Parameter check failed !");
        return false;
    }
    SignerConfig signerConfig;
    if (!SignElf::Sign(signerConfig, signParams)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] sign elf failed");
        return false;
    }
    return true;
}
} // namespace SignatureTools
} // namespace OHOS