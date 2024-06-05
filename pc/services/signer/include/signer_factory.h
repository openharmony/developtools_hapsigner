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
#ifndef SINATURETOOLS_SIGNER_FACTORY_H
#define SINATURETOOLS_SIGNER_FACTORY_H

#include "local_signer.h"
#include "localization_adapter.h"
#include "param_constants.h"
#include <dlfcn.h>

namespace OHOS {
    namespace SignatureTools {

        typedef struct RemoteSignerParam_type_st {
            const char* data;
            int64_t len;
        } RemoteSignerParamType;

        typedef ISigner* (*RemoteSignerCreator)(RemoteSignerParamType,
                                                RemoteSignerParamType,
                                                RemoteSignerParamType,
                                                RemoteSignerParamType,
                                                RemoteSignerParamType);

        class SignerFactory {
        public:
            SignerFactory() = default;
            ~SignerFactory() = default;

            std::shared_ptr<ISigner> GetSigner(LocalizationAdapter& adapter) const;

        private:
            std::shared_ptr<ISigner> LoadRemoteSigner(LocalizationAdapter& adapter) const;
        };
    }
}
#endif