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

#include "signer_factory.h"

namespace OHOS {
namespace SignatureTools {
std::shared_ptr<Signer> SignerFactory::LoadRemoteSigner() const
{
    std::string keyAlias = "oh-app1-key-v1";
    std::string signServer = "./dist/app-release1.pem";
    std::string onlineAuthMode = "./dist/OpenHarmony.p12";
    std::string username = "123456";
    std::string userPwd = "123456";

    // open so
    RemoteSignProvider::handle = dlopen("../src/libRemoteSigner.so", RTLD_NOW | RTLD_GLOBAL);
    if (!RemoteSignProvider::handle) {
        fprintf(stderr, "%s\n", dlerror());
        return nullptr;
    }

    // clear previous error
    dlerror();

    // get "Create" function
    RemoteSignerCreator remoteSignerCreator = (RemoteSignerCreator)dlsym(RemoteSignProvider::handle, "Create");
    char* error = nullptr;
    if ((error = dlerror()) != NULL) {
        fprintf(stderr, "%s\n", error);
        return nullptr;
    }

    RemoteSignerParamType keyAliasType { keyAlias.c_str(), keyAlias.size() };
    RemoteSignerParamType signServerType { signServer.c_str(), signServer.size() };
    RemoteSignerParamType onlineAuthModeType { onlineAuthMode.c_str(), onlineAuthMode.size() };
    RemoteSignerParamType usernameType { username.c_str(), username.size() };
    RemoteSignerParamType userPwdType { userPwd.c_str(), userPwd.size() };

    Signer* signer = remoteSignerCreator(keyAliasType, signServerType, onlineAuthModeType, usernameType, userPwdType);
    userPwd.clear();

    std::shared_ptr<Signer> remoteSigner(signer);

    return remoteSigner;
}

} // namespace SignatureTools
} // namespace OHOS