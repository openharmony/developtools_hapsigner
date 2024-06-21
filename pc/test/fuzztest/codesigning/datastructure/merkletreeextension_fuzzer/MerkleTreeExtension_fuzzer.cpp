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
#include "merkle_tree_extension.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool FromByteArray001(const uint8_t* data, size_t size)
{
    // 走进第一个分支:inMerkleTreeSize = 4095
    std::shared_ptr<MerkleTreeExtension> api = std::make_shared<MerkleTreeExtension>();

    ByteBuffer byteBuffer(8);
    byteBuffer.PutInt64(4095);
    byteBuffer.Flip();

    char readComment[8] = { 0 };
    byteBuffer.GetData(readComment, 8);
    std::vector<signed char> bytes(readComment, readComment + 8);

    Extension* pExtension = api->FromByteArray(bytes);

    return pExtension == nullptr;
}

bool FromByteArray002(const uint8_t* data, size_t size)
{
    // 走进第二个分支:inMerkleTreeOffset = 4095
    std::shared_ptr<MerkleTreeExtension> api = std::make_shared<MerkleTreeExtension>();

    ByteBuffer byteBuffer(16);
    byteBuffer.PutInt64(4096);
    byteBuffer.PutInt64(4095); // inMerkleTreeOffset
    byteBuffer.Flip();

    char readComment[16] = { 0 };
    byteBuffer.GetData(readComment, 16);
    std::vector<signed char> bytes(readComment, readComment + 16);

    Extension* pExtension = api->FromByteArray(bytes);

    return pExtension == nullptr;
}

bool FromByteArray003(const uint8_t* data, size_t size)
{
    // 走完
    std::shared_ptr<MerkleTreeExtension> api = std::make_shared<MerkleTreeExtension>();

    ByteBuffer byteBuffer(16);
    byteBuffer.PutInt64(4096);
    byteBuffer.PutInt64(4096); // inMerkleTreeOffset
    byteBuffer.Flip();

    char readComment[16] = { 0 };
    byteBuffer.GetData(readComment, 16);
    std::vector<signed char> bytes(readComment, readComment + 16);

    Extension* pExtension = api->FromByteArray(bytes);

    return pExtension == nullptr;
}

bool GetMerkleTreeOffset(const uint8_t* data, size_t size)
{
    std::shared_ptr<MerkleTreeExtension> api = std::make_shared<MerkleTreeExtension>();

    int64_t merkleTreeOffset = api->GetMerkleTreeOffset();

    return merkleTreeOffset == 0;
}

bool GetMerkleTreeSize(const uint8_t* data, size_t size)
{
    std::shared_ptr<MerkleTreeExtension> api = std::make_shared<MerkleTreeExtension>();

    int64_t merkleTreeSize = api->GetMerkleTreeSize();

    return merkleTreeSize == 0;
}

bool GetSize(const uint8_t* data, size_t size)
{
    std::shared_ptr<MerkleTreeExtension> api = std::make_shared<MerkleTreeExtension>();

    int32_t merkleTreeExtensionSize = api->GetSize();

    return merkleTreeExtensionSize == 88;
}

bool IsType(const uint8_t* data, size_t size)
{
    std::shared_ptr<MerkleTreeExtension> api = std::make_shared<MerkleTreeExtension>();

    int32_t type = 1;
    bool bIsType = api->IsType(type);

    return bIsType == true;
}

bool SetMerkleTreeOffset(const uint8_t* data, size_t size)
{
    std::shared_ptr<MerkleTreeExtension> api = std::make_shared<MerkleTreeExtension>();

    int64_t offset = 927046;
    api->SetMerkleTreeOffset(offset);

    return true;
}

bool ToByteArray(const uint8_t* data, size_t size)
{
    std::shared_ptr<MerkleTreeExtension> api = std::make_shared<MerkleTreeExtension>();

    std::vector<int8_t> byteArray = api->ToByteArray();

    return byteArray.size() == 88;
}

bool ToString(const uint8_t* data, size_t size)
{
    std::shared_ptr<MerkleTreeExtension> api = std::make_shared<MerkleTreeExtension>();

    std::string str = api->ToString();

    return str.size() == 0;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FromByteArray001(data, size);
    OHOS::FromByteArray002(data, size);
    OHOS::FromByteArray003(data, size);
    OHOS::GetMerkleTreeOffset(data, size);
    OHOS::GetMerkleTreeSize(data, size);
    OHOS::GetSize(data, size);
    OHOS::IsType(data, size);
    OHOS::SetMerkleTreeOffset(data, size);
    OHOS::ToByteArray(data, size);
    OHOS::ToString(data, size);
    return 0;
}