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
#include "signed_file_pos.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool FromByteArray(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignedFilePos> api = std::make_shared<SignedFilePos>(108, 31, 280, 2068);

    std::vector<int8_t> bytes = { 11, -93, 88, 107, -121, 96, 121, 23, -64, -58, -95, -71,
        -126, 60, 116, 60, 10, 15, -125, 107, 127, -123, 81, 68, 28, -121, -20, -42, -116,
        -81, -6, 118, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0 };
    api->FromByteArray(bytes);

    return true;
}

bool GetFileNameOffset(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignedFilePos> api = std::make_shared<SignedFilePos>(108, 31, 280, 2068);

    int32_t offset = api->GetFileNameOffset();

    return offset == 108;
}

bool GetFileNameSize(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignedFilePos> api = std::make_shared<SignedFilePos>(108, 31, 280, 2068);

    int32_t fileNameSize = api->GetFileNameSize();

    return fileNameSize == 31;
}

bool GetSignInfoOffset(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignedFilePos> api = std::make_shared<SignedFilePos>(108, 31, 280, 2068);

    int32_t signInfoOffset = api->GetSignInfoOffset();

    return signInfoOffset == 280;
}

bool GetSignInfoSize(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignedFilePos> api = std::make_shared<SignedFilePos>(108, 31, 280, 2068);

    int32_t signInfoSize = api->GetSignInfoSize();

    return signInfoSize == 2068;
}

bool IncreaseFileNameOffset(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignedFilePos> api = std::make_shared<SignedFilePos>(108, 31, 280, 2068);

    api->IncreaseFileNameOffset(1);

    return true;
}

bool IncreaseSignInfoOffset(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignedFilePos> api = std::make_shared<SignedFilePos>(108, 31, 280, 2068);

    api->IncreaseSignInfoOffset(2);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FromByteArray(data, size);
    OHOS::GetFileNameOffset(data, size);
    OHOS::GetFileNameSize(data, size);
    OHOS::GetSignInfoOffset(data, size);
    OHOS::GetSignInfoSize(data, size);
    OHOS::IncreaseFileNameOffset(data, size);
    OHOS::IncreaseSignInfoOffset(data, size);
    return 0;
}