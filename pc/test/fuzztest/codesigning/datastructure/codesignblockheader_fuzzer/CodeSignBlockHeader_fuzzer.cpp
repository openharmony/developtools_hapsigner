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
#include "code_sign_block_header.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool FromByteArray001(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    std::vector<signed char> bytes;
    CodeSignBlockHeader* codeSignBlockHeader = api->FromByteArray(bytes);

    return codeSignBlockHeader == nullptr;
}

bool FromByteArray002(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    std::vector<signed char> bytes{ -1, -91, 34, -16, 97, -32, -121, 1, 5, 3, 8, 8, 15,
        12, 12, 13, 58, 19, 50, 10, 54, 29, 59, 17, 102, 105, 15, 19, 29, 30, 32, 59 };
    CodeSignBlockHeader* codeSignBlockHeader = api->FromByteArray(bytes);

    return codeSignBlockHeader == nullptr;
}

bool FromByteArray003(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    ByteBuffer byteBuffer(33);
    byteBuffer.PutInt64(-2285919006713316147);
    byteBuffer.PutInt32(2);
    byteBuffer.Flip();
    char readComment[32] = { 0 };
    byteBuffer.GetData(readComment, 32);
    std::vector<signed char> bytes(readComment, readComment + 32);
    CodeSignBlockHeader* codeSignBlockHeader = api->FromByteArray(bytes);

    return codeSignBlockHeader == nullptr;
}

bool FromByteArray004(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    ByteBuffer byteBuffer(33);
    byteBuffer.PutInt64(-2285919006713316147);
    byteBuffer.PutInt32(1);
    byteBuffer.PutInt32(4);  // inBlockSize
    byteBuffer.PutInt32(4);  // inSegmentNum
    byteBuffer.Flip();
    char readComment[32] = { 0 };
    byteBuffer.GetData(readComment, 32);
    std::vector<signed char> bytes(readComment, readComment + 32);
    CodeSignBlockHeader* codeSignBlockHeader = api->FromByteArray(bytes);

    return codeSignBlockHeader == nullptr;
}

bool FromByteArray005(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    ByteBuffer byteBuffer(33);
    byteBuffer.PutInt64(-2285919006713316147);
    byteBuffer.PutInt32(1);
    byteBuffer.PutInt32(4);  // inBlockSize
    byteBuffer.PutInt32(3);  // inSegmentNum
    byteBuffer.PutInt32(-1); // inFlags
    byteBuffer.Flip();
    char readComment[32] = { 0 };
    byteBuffer.GetData(readComment, 32);
    std::vector<signed char> bytes(readComment, readComment + 32);
    CodeSignBlockHeader* codeSignBlockHeader = api->FromByteArray(bytes);
    return codeSignBlockHeader == nullptr;
}

bool FromByteArray006(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    ByteBuffer byteBuffer(33);
    byteBuffer.PutInt64(-2285919006713316147);
    byteBuffer.PutInt32(1);
    byteBuffer.PutInt32(4);  // inBlockSize
    byteBuffer.PutInt32(3);  // inSegmentNum
    byteBuffer.PutInt32(0);  // inFlags
    byteBuffer.Flip();
    char readComment[32] = { 0 };
    byteBuffer.GetData(readComment, 32);
    std::vector<signed char> bytes(readComment, readComment + 32);
    CodeSignBlockHeader* codeSignBlockHeader = api->FromByteArray(bytes);

    return codeSignBlockHeader != nullptr;
}

bool GetBlockSize(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    int blockSize = api->GetBlockSize();

    return blockSize == 0;
}

bool GetSegmentNum(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    int segmentNum = api->GetSegmentNum();

    return segmentNum == 0;
}

bool SetBlockSize(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    api->SetBlockSize(1024);

    return api->GetBlockSize() == 1024;
}

bool SetFlags(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    int flags = 1;
    api->SetFlags(flags);

    return flags == 1;
}

bool SetSegmentNum(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    api->SetSegmentNum(4);

    return api->GetSegmentNum() == 4;
}

bool Size(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    int headerSize = api->Size();

    return headerSize == 32;
}

bool ToByteArray(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::shared_ptr<CodeSignBlockHeader> api = std::make_shared<CodeSignBlockHeader>();
    std::vector<int8_t> byteArray = api->ToByteArray();

    return byteArray.size() == 32;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FromByteArray001(data, size);
    OHOS::FromByteArray002(data, size);
    OHOS::FromByteArray003(data, size);
    OHOS::FromByteArray004(data, size);
    OHOS::FromByteArray005(data, size);
    OHOS::FromByteArray006(data, size);
    OHOS::GetBlockSize(data, size);
    OHOS::GetSegmentNum(data, size);
    OHOS::SetBlockSize(data, size);
    OHOS::SetFlags(data, size);
    OHOS::SetSegmentNum(data, size);
    OHOS::Size(data, size);
    OHOS::ToByteArray(data, size);
    return 0;
}