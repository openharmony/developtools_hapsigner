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

#ifndef SIGNERTOOLS_PARAMSTRUSTLIST_H
#define SIGNERTOOLS_PARAMSTRUSTLIST_H

#include <string>
#include <vector>
#include <fstream>
#include <unordered_map>
#include "signature_tools_log.h"
#include "hap_verify_result.h"
#include "method.h"

namespace OHOS {
    namespace SignatureTools {
        class ParamsTrustlist final {
        public:
            ParamsTrustlist()
            {
                commands.push_back(Method::GENERATE_KEYPAIR + options);
                commands.push_back(Method::GENERATE_CSR + options);
                commands.push_back(Method::GENERATE_CERT + options);
                commands.push_back(Method::GENERATE_CA + options);
                commands.push_back(Method::GENERATE_APP_CERT + options);
                commands.push_back(Method::GENERATE_PROFILE_CERT + options);
                commands.push_back(Method::SIGN_PROFILE + options);
                commands.push_back(Method::VERIFY_PROFILE + options);
                commands.push_back(Method::SIGN_APP + options);
                commands.push_back(Method::VERIFY_APP + options);
            }
            /**
             * Define generic string
             */
        public:
            static const std::string options;
            bool GenerateTrustlist();
            std::vector<std::string> GetTrustList(const std::string& commond);

            /**
             * Define commond list
             */
        private:
            static std::vector<std::string> commands;

            /**
             * Define trust map
             */
            static std::unordered_map<std::string, std::vector<std::string>> trustMap;

            void ReadHelpParam(std::ifstream& fd);
            void PutTrustMap(const std::string& cmd_stand_by, const std::string& param);
            std::string Trim(const std::string& str);
        };
    } // namespace SignatureTools
} // namespace OHOS
#endif
