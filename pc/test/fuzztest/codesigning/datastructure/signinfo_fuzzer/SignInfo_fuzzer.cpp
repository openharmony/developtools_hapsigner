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
#include "sign_info.h"
#include "byte_buffer.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool FromByteArray(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignInfo> api = std::make_shared<SignInfo>();

    std::vector<int8_t> bytes = { 11, -93, 88, 107, -121, 96, 121, 23, -64, -58, -95,
        -71, -126, 60, 116, 60, 10, 15, -125, 107, 127, -123, 81, 68, 28, -121, -20,
        -42, -116, -81, -6, 118, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    api->FromByteArray(bytes);

    return true;
}

bool GetDataSize(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignInfo> api = std::make_shared<SignInfo>();

    int64_t dataSize = api->GetDataSize();

    return dataSize == 0;
}

bool GetExtensionByType(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignInfo> api = std::make_shared<SignInfo>();

    int32_t type = 1;
    Extension* pExtension = api->GetExtensionByType(type);

    return pExtension == nullptr;
}

bool GetExtensionNum(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignInfo> api = std::make_shared<SignInfo>();
    
    int32_t extensionNum = api->GetExtensionNum();

    return extensionNum == 0;
}

bool GetSignature(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignInfo> api = std::make_shared<SignInfo>();

    std::vector<int8_t> signatureVec = api->GetSignature();

    return signatureVec.size() == 0;
}

bool GetSize(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignInfo> api = std::make_shared<SignInfo>();

    int32_t sizeInt = api->GetSize();

    return sizeInt == 60;
}

bool ParseMerkleTreeExtension(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignInfo> api = std::make_shared<SignInfo>();

    std::vector<int8_t> bytes = std::vector<int8_t>{ 1, 0, 0, 0, 80, 0, 0, 0, 0, 16, 0, 0,
        0, 0, 0, 0, 0, 96, 21, 0, 0, 0, 0, 0, 75, 43, 18, -27, 86, 118, 101, 64, -128, -112,
        84, 68, 4, -107, 110, 92, 33, -118, 113, -65, -79, -103, 40, 59, 82, -90, -87, -115,
        27, 77, 3, 95, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0 };
    ByteBuffer bf((int32_t)bytes.size());
    bf.PutData((char*)bytes.data(), bytes.size());

    std::vector<MerkleTreeExtension*> extensionVec = api->ParseMerkleTreeExtension(&bf, 1);

    return extensionVec.size() == 0;
}

bool ToByteArray(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignInfo> api = std::make_shared<SignInfo>();

    std::vector<int8_t> bytes = api->ToByteArray();

    return bytes.size() == 60;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FromByteArray(data, size);
    OHOS::GetDataSize(data, size);
    OHOS::GetExtensionByType(data, size);
    OHOS::GetExtensionNum(data, size);
    OHOS::GetSignature(data, size);
    OHOS::GetSize(data, size);
    OHOS::ParseMerkleTreeExtension(data, size);
    OHOS::ToByteArray(data, size);
    return 0;
}