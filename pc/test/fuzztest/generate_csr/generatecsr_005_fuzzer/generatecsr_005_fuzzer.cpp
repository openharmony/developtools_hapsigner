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

#include <cstddef>
#include <cstdint>
#include <memory>
#include "securec.h"
#include "sign_tool_service_impl.h"

namespace OHOS {
namespace SignatureTools {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    SignToolServiceImpl api;
    Options params;

    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";
    
    params["keyAlias"] = std::string("oh-app1-key-v1");
    params["keyPwd"] = keyPwd;
    params["subject"] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release");
    params["signAlg"] = std::string(reinterpret_cast<const char*>(data), size);
    params["keystoreFile"] = std::string("/data/test/generateCsr/ohtest.p12");
    params["keystorePwd"] = keystorePwd;
    params["outFile"] = std::string("/data/test/generateCsr/oh-app1-key-v1.csr");

    bool ret = api.GenerateCsr(&params);
    return ret;
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SignatureTools::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}