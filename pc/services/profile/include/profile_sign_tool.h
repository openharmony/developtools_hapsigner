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
#ifndef SIGNERTOOLS_PROFILESIGNTOOOL_H
#define SIGNERTOOLS_PROFILESIGNTOOOL_H
#include <memory>
#include <string>
#include "openssl/pkcs7.h"
#include "openssl/err.h"
#include "openssl/x509.h"
#include "isigner.h"
    namespace OHOS {
    namespace SignatureTools {
        /**
         * To sign and verify profile.
         *
         * @since 2021/12/28
         */
        class ISigner;
        class LocalizationAdapter;
        class PKCS7Data;
        class ProfileSignTool {
        private:
            ProfileSignTool();
            /**
           * generateP7b.
           *
           * @param adapter local adapter with params
           * @param content content to sign
           * @ret signed content
           * @return 0:success <0:error
           */
        public:
            static int GenerateP7b(LocalizationAdapter& adapter, const std::string& content, std::string& ret);
            /**
              * signProfile.
              *
              * @param content content to sign
              * @param signer signer
              * @param sigAlg sign algorithm  only SHAwith256 or SHAwith384
              * @ret signed data
              * @return 0:success <0:error
              */
            static int SignProfile(const std::string& content,
            std::shared_ptr<ISigner> signer, const std::string& sigAlg, std::string& ret);
        };
    }
}
#endif