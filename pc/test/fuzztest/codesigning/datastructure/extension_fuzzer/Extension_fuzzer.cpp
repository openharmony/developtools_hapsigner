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
#include "extension.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool GetSize(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<Extension> api = std::make_shared<Extension>();

    int32_t sizeInt = api->GetSize();

    return sizeInt == 0;
}

bool IsType(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<Extension> api = std::make_shared<Extension>();

    int32_t type = 1;
    bool bIsType = api->IsType(type);

    return bIsType == false;
}

bool ToByteArray(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<Extension> api = std::make_shared<Extension>();
   
    std::vector<int8_t> byteArray = api->ToByteArray();

    return byteArray.size() == 8;
}

bool ToString(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<Extension> api = std::make_shared<Extension>();

    std::string str = api->ToString();

    return str.size() == 27;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetSize(data, size);
    OHOS::IsType(data, size);
    OHOS::ToByteArray(data, size);
    OHOS::ToString(data, size);
    return 0;
}