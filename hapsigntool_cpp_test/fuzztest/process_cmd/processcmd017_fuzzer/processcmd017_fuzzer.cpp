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
    if (!data || size <= 0) {
        return true;
    }

    char arg0[] = "";
    char arg1[] = "verify-profile";
    char arg2[] = "-inFile";
    char arg3[] = "./generateKeyPair/signed-profile.p7b";
    char arg4[] = "-outFile";
    char* arg5 = new char[size];
    memcpy_s(arg5, size, data, size);
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5 };
    int argc = 6;

    bool ret = ParamsRunTool::ProcessCmd(argv, argc);
    delete[] arg5;
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