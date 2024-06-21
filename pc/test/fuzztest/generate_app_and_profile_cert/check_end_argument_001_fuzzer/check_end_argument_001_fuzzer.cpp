/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <stddef.h>
#include <stdint.h>
#include "sign_tool_service_impl.h"
#include "params_run_tool.h"
#include "options.h"

namespace OHOS {
namespace SignatureTools {

    void CheckEndCertArgumentTest3(const std::string& data)
    {
        Options option;
        option[Options::KEY_ALIAS] = "oh-app1-key-v1";
        option[Options::ISSUER] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
        option[Options::ISSUER_KEY_ALIAS] = data;
        option[Options::SUBJECT] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
        option[Options::SIGN_ALG] = "SHA384withECDSA";
        option[Options::OUT_FORM] = "certChain";
 
        ParamsRunTool::CheckEndCertArguments(option);
    }

    void CheckEndCertArgumentTest2(const std::string& data)
    {
        Options option;
        option[Options::KEY_ALIAS] = data;
        option[Options::ISSUER] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
        option[Options::ISSUER_KEY_ALIAS] = "oh-app-sign-srv-ca-key-v1";
        option[Options::SUBJECT] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
        option[Options::SIGN_ALG] = "SHA384withECDSA";
        option[Options::OUT_FORM] = "certChain";

        ParamsRunTool::CheckEndCertArguments(option);
    }

    void CheckEndCertArgumentTest1(const uint8_t* data, size_t size)
    { 
        Options option;
        std::string str(reinterpret_cast<const char*>(data), size);
        option[Options::KEY_ALIAS] = "oh-app1-key-v1";
        option[Options::ISSUER] = str;
        option[Options::ISSUER_KEY_ALIAS] = "oh-app-sign-srv-ca-key-v1";
        option[Options::SUBJECT] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
        option[Options::SIGN_ALG] = "SHA384withECDSA";
        option[Options::OUT_FORM] = "certChain";
        
        ParamsRunTool::CheckEndCertArguments(option);
        CheckEndCertArgumentTest2(str);
        CheckEndCertArgumentTest3(str);
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SignatureTools::CheckEndCertArgumentTest1(data, size);
    return 0;
}