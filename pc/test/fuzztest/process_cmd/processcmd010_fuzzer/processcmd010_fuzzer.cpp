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

    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias",
        arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA", arg12[] = "-keystoreFile",
        arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21 };
    int argc = 22;

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