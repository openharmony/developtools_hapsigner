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
#ifndef SINATURETOOLS_REMOTE_SIGNER_H
#define SINATURETOOLS_REMOTE_SIGNER_H

#include <memory>

#include "remote_signer_log.h"
#include "signer.h"

namespace OHOS {
namespace SignatureTools {
class RemoteSigner : public Signer {
public:
    RemoteSigner(std::string _keyAlias, std::string _signServer, std::string _onlineAuthMode, std::string _username,
        std::string _userPwd);
    ~RemoteSigner();

    std::string GetSignature(const std::string& data, const std::string& signAlg) const override;
    STACK_OF(X509_CRL)* GetCrls() const override;
    STACK_OF(X509)* GetCertificates() const override;

private:
    std::string keyAlias;
    std::string signServer;
    std::string onlineAuthMode;
    std::string username;
    std::string userPwd;
};

} // namespace SignatureTools
} // namespace OHOS

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RemoteSignerParamTypeSt {
    const char* data;
    size_t len;
} RemoteSignerParamType;

OHOS::SignatureTools::Signer* Create(RemoteSignerParamType keyAlias, RemoteSignerParamType signServer,
    RemoteSignerParamType onlineAuthMode, RemoteSignerParamType username, RemoteSignerParamType userPwd);

#ifdef __cplusplus
}
#endif

#endif // SINATURETOOLS_REMOTE_SIGNER_H