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
#include <cstdio>
#include "params_run_tool.h"

namespace OHOS {
namespace SignatureTools {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }

    char arg0[] = "", arg1[] = "generate-app-cert", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-app-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA256withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/app-release1.pem",
        arg22[] = "-subCaCertFile", arg23[] = "./generateKeyPair/app-sign-srv-ca1.cer",
        arg24[] = "-outForm", arg25[] = "certChain", arg26[] = "-rootCaCertFile",
        arg27[] = "./generateKeyPair/root-ca1.cer",
        arg28[] = "-issuerKeyPwd", arg29[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21,
                     arg22, arg23, arg24, arg25, arg26, arg27, arg28, arg29 };
    int argc = 30;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);
	return ret;
}
} // namespace SignatureTools
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SignatureTools::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}