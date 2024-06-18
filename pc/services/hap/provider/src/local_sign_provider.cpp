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
#include "local_sign_provider.h"
#include "params.h"

namespace OHOS {
namespace SignatureTools {
std::optional<X509_CRL*> LocalSignProvider::GetCrl()
{
    return std::optional<X509_CRL*>();
}

bool LocalSignProvider::CheckParams(Options* options)
{
    if (!SignProvider::CheckParams(options)) {
        SIGNATURE_TOOLS_LOGE("Parameter check failed !");
        return false;
    }
    std::vector<std::string> paramFileds;
    paramFileds.emplace_back(ParamConstants::PARAM_LOCAL_JKS_KEYSTORE);
    paramFileds.emplace_back(ParamConstants::PARAM_LOCAL_JKS_KEYSTORE_CODE);
    paramFileds.emplace_back(ParamConstants::PARAM_LOCAL_JKS_KEYALIAS_CODE);
    std::unordered_set<std::string> paramSet = Params::InitParamField(paramFileds);
    for (auto it = options->begin(); it != options->end(); it++) {
        if (paramSet.find(it->first) != paramSet.end()) {
            size_t size = it->first.size();
            std::string str = it->first.substr(size - 3);
            if (str == "Pwd") {
                std::string strPwd = options->GetChars(it->first);
                signParams.insert(std::make_pair(it->first, strPwd));
            } else {
                signParams.insert(std::make_pair(it->first, options->GetString(it->first)));
            }
        }
    }
    if (!CheckSignCode()) {
        SIGNATURE_TOOLS_LOGE("Error: PARAM_SIGN_CODE Parameter check error !");
        return false;
    }
    if (!CheckPublicKeyPath()) {
        SIGNATURE_TOOLS_LOGE("Error: appCertFile Parameter check error !");
        return false;
    }
    return true;
}

bool LocalSignProvider::CheckPublicKeyPath()
{
    std::string publicCertsFile = signParams[ParamConstants::PARAM_LOCAL_PUBLIC_CERT];
    if (!FileUtils::IsValidFile(publicCertsFile)) {
        PrintErrorNumberMsg("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR, publicCertsFile + "not support");
        return false;
    }
    std::ifstream publicKeyFile(publicCertsFile);
    if (!publicKeyFile.is_open()) {
        SIGNATURE_TOOLS_LOGE("File opening failure %{public}s", publicCertsFile.c_str());
        publicKeyFile.close();
        return false;
    }
    publicKeyFile.close();
    return true;
}
} // namespace SignatureTools
} // namespace OHOS