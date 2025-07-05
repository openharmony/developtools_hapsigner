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
#ifndef SIGNATRUETOOLS_SELF_SIGN_SIGN_PROVIDER_H
#define SIGNATRUETOOLS_SELF_SIGN_SIGN_PROVIDER_H

#include "sign_provider.h"

namespace OHOS {
namespace SignatureTools {
class SelfSignSignProvider : public SignProvider {
public:
    SelfSignSignProvider() = default;
    ~SelfSignSignProvider() = default;
    bool SignElf(Options* options);
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_SELF_SIGN_SIGN_PROVIDER_H