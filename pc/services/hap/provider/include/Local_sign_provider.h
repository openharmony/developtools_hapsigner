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

#ifndef SIGNERTOOLS_LOCAL_SIGN_PROVIDER_H
#define SIGNERTOOLS_LOCAL_SIGN_PROVIDER_H

#include "sign_provider.h"
namespace OHOS {
    namespace SignatureTools {
        class LocalJKSSignProvider : public SignProvider {
            public:
                LocalJKSSignProvider() = default;
                ~LocalJKSSignProvider() = default;

                std::optional<X509_CRL*> GetCrl();
                bool CheckParams(Options* options);
            private:
                bool CheckPublicKeyPath();
        };
    }
}
#endif