/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef SIGNERTOOLS_METHOD_H
#define SIGNERTOOLS_METHOD_H
#include "signature_tools_log.h"
#include <string>
namespace OHOS {
    namespace SignatureTools {
        class Method final {
            /**
             * Generate app cert method name.
             */
        public:
            static const std::string GENERATE_APP_CERT;
            /**
         * Generate ca method name.
         */
            static const std::string GENERATE_CA;
            /**
         * Generate cert method name.
         */
            static const std::string GENERATE_CERT;
            /**
         * Generate csr method name.
         */
            static const std::string GENERATE_CSR;
            /**
         * Generate key pair method name.
         */
            static const std::string GENERATE_KEYPAIR;
            /**
         * Generate profile cert method name.
         */
            static const std::string GENERATE_PROFILE_CERT;
            /**
         * Sign app method name.
         */
            static const std::string SIGN_APP;
            /**
         * Sign profile method name.
         */
            static const std::string SIGN_PROFILE;
            /**
         * Verify app method name.
         */
            static const std::string VERIFY_APP;
            /**
         * Verify profile method name.
         */
            static const std::string VERIFY_PROFILE;
        };
    } // namespace SignatureTools
} // namespace OHOS
#endif
