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

    char arg0[] = "", arg1[] = "sign-app", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-mode", arg7[] = "localSign", arg8[] = "-signCode",
        arg9[] = "1", arg10[] = "-signAlg", arg11[] = "SHA256withECDSA",
        arg12[] = "-appCertFile", arg13[] = "./generateKeyPair/app-release1.pem",
        arg14[] = "-profileFile", arg15[] = "./generateKeyPair/signed-profile.p7b",
        arg16[] = "-inFile", arg17[] = "./generateKeyPair/entry-default-unsigned-so.hap", arg18[] = "-keystoreFile",
        arg19[] = "./generateKeyPair/OpenHarmony.p12",
        arg20[] = "-keystorePwd", arg21[] = "123456", arg22[] = "-outFile",
        arg23[] = "./generateKeyPair/entry-default-signed-so.hap";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);
	return ret;
}

bool SignElf(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }

    char arg0[] = "", arg1[] = "sign-app", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-mode", arg7[] = "localSign", arg8[] = "-signCode",
        arg9[] = "1", arg10[] = "-signAlg", arg11[] = "SHA256withECDSA",
        arg12[] = "-appCertFile", arg13[] = "./generateKeyPair/app-release1.pem",
        arg14[] = "-profileFile", arg15[] = "./generateKeyPair/signed-profile.p7b",
        arg16[] = "-inFile", arg17[] = "./generateKeyPair/entry-default-unsigned-so.hap", arg18[] = "-keystoreFile",
        arg19[] = "./generateKeyPair/OpenHarmony.p12",
        arg20[] = "-keystorePwd", arg21[] = "123456", arg22[] = "-outFile",
        arg23[] = "./generateKeyPair/entry-default-signed-so.elf",
        arg24[] = "-inForm", arg25[] = "elf";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23, arg24, arg25 };
    int argc = 26;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);
	return ret;
}

bool SignBin(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }

    char arg0[] = "", arg1[] = "sign-app", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-mode", arg7[] = "localSign", arg8[] = "-signCode",
        arg9[] = "1", arg10[] = "-signAlg", arg11[] = "SHA256withECDSA",
        arg12[] = "-appCertFile", arg13[] = "./generateKeyPair/app-release1.pem",
        arg14[] = "-profileFile", arg15[] = "./generateKeyPair/signed-profile.p7b",
        arg16[] = "-inFile", arg17[] = "./generateKeyPair/entry-default-unsigned-so.hap", arg18[] = "-keystoreFile",
        arg19[] = "./generateKeyPair/OpenHarmony.p12",
        arg20[] = "-keystorePwd", arg21[] = "123456", arg22[] = "-outFile",
        arg23[] = "./generateKeyPair/entry-default-signed-so.bin",
        arg24[] = "-inForm", arg25[] = "bin";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23, arg24, arg25 };
    int argc = 26;

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
    OHOS::SignatureTools::SignElf(data, size);
    OHOS::SignatureTools::SignBin(data, size);
    return 0;
}