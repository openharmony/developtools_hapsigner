/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "params_trust_list.h"
#include "constant.h"
#include "params.h"

namespace OHOS {
namespace SignatureTools {
std::vector<std::string> ParamsTrustlist::commands;
std::unordered_map<std::string, std::vector<std::string>> ParamsTrustlist::trustMap;
const std::string ParamsTrustlist::options = " [options]:";

ParamsTrustlist::ParamsTrustlist()
{
    commands.push_back(Params::GENERATE_KEYPAIR + options);
    commands.push_back(Params::GENERATE_CSR + options);
    commands.push_back(Params::GENERATE_CERT + options);
    commands.push_back(Params::GENERATE_CA + options);
    commands.push_back(Params::GENERATE_APP_CERT + options);
    commands.push_back(Params::GENERATE_PROFILE_CERT + options);
    commands.push_back(Params::SIGN_PROFILE + options);
    commands.push_back(Params::VERIFY_PROFILE + options);
    commands.push_back(Params::SIGN_APP + options);
    commands.push_back(Params::VERIFY_APP + options);
}

std::string ParamsTrustlist::Trim(const std::string& str)
{
    size_t start = str.find_first_not_of("    \n\r ");
    if (start == std::string::npos) {
        return "";
    }
    size_t end = str.find_last_not_of("     \n\r");
    if (end == std::string::npos) {
        return "";
    }
    return str.substr(start, end - start + 1);
}

void ParamsTrustlist::PutTrustMap(const std::string& cmdStandBy, const std::string& param)
{
    if (param.at(0) == '-') {
        size_t pos = param.find(':');
        std::string subParam = param.substr(0, pos);
        subParam = Trim(subParam);
        bool isExists = false;
        if (trustMap.find(cmdStandBy) != trustMap.end()) {
            isExists = true;
        }
        std::vector<std::string> trustList = isExists ? trustMap[cmdStandBy] : std::vector<std::string>();
        trustList.push_back(subParam);
        trustMap[cmdStandBy] = trustList;
    }
}

void ParamsTrustlist::ReadHelpParam(std::ifstream& fd)
{
    std::string str;
    std::string cmdStandBy;
    while (!fd.eof() && std::getline(fd, str)) {
        bool isExists = false;
        std::string params = Trim(str);
        if (params.empty()) {
            continue;
        }
        for (const auto& it : commands) {
            if (it == params) {
                cmdStandBy = params;
                isExists = true;
                break;
            }
        }
        if (!isExists) {
            PutTrustMap(cmdStandBy, params);
        }
    }
}

bool ParamsTrustlist::GenerateTrustlist()
{
    std::ifstream fd;
    fd.open(HELP_FILE_PATH.c_str());
    if (!fd.is_open()) {
        PrintErrorNumberMsg("OPEN_FILE_ERROR", OPEN_FILE_ERROR, "Open " + HELP_FILE_PATH + " failed");
        return false;
    }
    ReadHelpParam(fd);
    return true;
}

std::vector<std::string> ParamsTrustlist::GetTrustList(const std::string& commond)
{
    std::vector<std::string> trustList;
    if (!GenerateTrustlist()) {
        return trustList;
    }
    std::string keyParam = commond + options;
    bool isExists = false;
    if (trustMap.find(keyParam) != trustMap.end()) {
        isExists = true;
    }
    return isExists ? trustMap[keyParam] : trustList;
}
} // namespace SignatureTools
} // namespace OHOS