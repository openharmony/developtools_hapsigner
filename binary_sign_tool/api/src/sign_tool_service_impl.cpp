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

#include "sign_tool_service_impl.h"
#include "pkcs7_data.h"
#include "profile_sign_tool.h"
#include "cJSON.h"
#include "profile_info.h"
#include "profile_verify.h"
#include "signature_tools_errno.h"
#include "self_sign_sign_provider.h"
#include "local_sign_provider.h"
#include "signature_tools_log.h"
#include "param_constants.h"
#include "constant.h"
#include "remote_sign_provider.h"
#include "verify_elf.h"

namespace OHOS {
namespace SignatureTools {
bool SignToolServiceImpl::Sign(Options* options)
{
    std::string inFile = options->GetString(Options::IN_FILE);
    if (!FileUtils::isElfFile(inFile)) {
        SIGNATURE_TOOLS_LOGE("inFile is not a elf file");
        return false;
    }
    std::string mode = options->GetString(Options::MODE);
    std::string selfSign = options->GetString(Options::SELF_SIGN);
    std::shared_ptr<SignProvider> signProvider;
    if (ParamConstants::SELF_SIGN_TYPE_1 == selfSign) {
        signProvider = std::make_shared<SelfSignSignProvider>();
    } else if (LOCAL_SIGN == mode) {
        signProvider = std::make_shared<LocalSignProvider>();
    } else if (REMOTE_SIGN == mode) {
        signProvider = std::make_shared<RemoteSignProvider>();
    } else {
        SIGNATURE_TOOLS_LOGE("Resign mode. But not implemented yet");
        return false;
    }
    return signProvider->SignElf(options);
}

int SignToolServiceImpl::GetProvisionContent(const std::string& input, std::string& ret)
{
    std::string bytes;
    if (FileUtils::ReadFile(input, bytes) < 0) {
        SIGNATURE_TOOLS_LOGE("provision read faild!");
        return IO_ERROR;
    }
    cJSON* root = cJSON_ParseWithOpts(bytes.c_str(), 0, 1);
    if (root == nullptr || !(cJSON_IsObject(root) || cJSON_IsArray(root))) {
        PrintErrorNumberMsg("PARSE ERROR", PARSE_ERROR, "Parsing appProvision failed!");
        if (root != nullptr) {
            cJSON_Delete(root);
        }
        return PARSE_ERROR;
    }
    char* jsonStr = cJSON_Print(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        SIGNATURE_TOOLS_LOGE("Failed to convert JSON to string!");
        return PARSE_ERROR;
    }
    ret = jsonStr;
    free(jsonStr);
    cJSON_Delete(root);
    ProfileInfo provision;
    AppProvisionVerifyResult result = ParseProvision(ret, provision);
    if (result != PROVISION_OK) {
        SIGNATURE_TOOLS_LOGE("invalid provision");
        return INVALIDPARAM_ERROR;
    }
    return 0;
}

bool SignToolServiceImpl::Verify(Options* option)
{
    VerifyElf verifyElf;
    if (!verifyElf.Verify(option)) {
        return false;
    }
    return true;
}
} // namespace SignatureTools
} // namespace OHOS
