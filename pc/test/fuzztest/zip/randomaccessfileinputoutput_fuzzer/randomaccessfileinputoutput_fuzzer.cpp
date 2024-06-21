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

#include "random_access_file.h"

using namespace OHOS::SignatureTools;
namespace OHOS {
void ReadFileFullyFromOffsetFuncV1(const uint8_t* data, size_t size)
{
    auto outputHap = std::make_shared<RandomAccessFile>();
    if (!outputHap->Init("./zip/test1.cpp")) {
        return;
    }
    std::string buf(1, 0);
    outputHap->ReadFileFullyFromOffset(buf.data(), 0, 1);
}

void WriteToFileFunc(const uint8_t* data, size_t size)
{
    auto outputHap = std::make_shared<RandomAccessFile>();
    if (!outputHap->Init("./zip/test1.cpp")) {
        return;
    }
    ByteBuffer buffer(1);
    buffer.PutByte(1);
    outputHap->WriteToFile(buffer, 0, 1);
}

void DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    ReadFileFullyFromOffsetFuncV1(data, size);
    WriteToFileFunc(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}