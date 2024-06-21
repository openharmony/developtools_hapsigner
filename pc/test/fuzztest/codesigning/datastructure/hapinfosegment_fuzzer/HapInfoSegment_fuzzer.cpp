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
#include "hap_info_segment.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool FromByteArray001(const uint8_t* data, size_t size)
{
    // 走第一个分支:inMagic 不一样
    std::shared_ptr<HapInfoSegment> api = std::make_shared<HapInfoSegment>();

    ByteBuffer byteBuffer(32);
    byteBuffer.PutInt32(0); // inMagic
    byteBuffer.Flip();

    char readComment[32] = { 0 };
    byteBuffer.GetData(readComment, 32);
    std::vector<signed char> bytes(readComment, readComment + 32);

    api->FromByteArray(bytes);

    return true;
}

bool FromByteArray002(const uint8_t* data, size_t size)
{
    // 走第三个分支:inHapSignInfo.getDataSize()
    std::shared_ptr<HapInfoSegment> api = std::make_shared<HapInfoSegment>();

    ByteBuffer byteBuffer(64);
    byteBuffer.PutInt32(-1045050266); // inMagic
    byteBuffer.PutInt32(0); // inSaltSize
    byteBuffer.PutInt32(0); // inSigSize
    byteBuffer.PutInt32(1); // inFlags
    byteBuffer.PutInt64(5); // inDataSize

    std::vector<int8_t> inSalt(32, 0);
    byteBuffer.PutData((const char*)inSalt.data(), 32);

    byteBuffer.PutInt32(1); // inExtensionNum
    byteBuffer.PutInt32(4); // inExtensionOffset

    byteBuffer.Flip();

    char readComment[64] = { 0 };
    byteBuffer.GetData(readComment, 64);
    std::vector<signed char> bytes(readComment, readComment + 64);

    api->FromByteArray(bytes);

    return true;
}

bool FromByteArray003(const uint8_t* data, size_t size)
{
    // 走第四个分支:inHapSignInfo.getExtensionNum()
    std::shared_ptr<HapInfoSegment> api = std::make_shared<HapInfoSegment>();

    ByteBuffer byteBuffer(64);
    byteBuffer.PutInt32(-1045050266); // inMagic
    byteBuffer.PutInt32(0); // inSaltSize
    byteBuffer.PutInt32(0); // inSigSize
    byteBuffer.PutInt32(1); // inFlags
    byteBuffer.PutInt64(4096); // inDataSize

    std::vector<int8_t> inSalt(32, 0);
    byteBuffer.PutData((const char*)inSalt.data(), 32);

    byteBuffer.PutInt32(2); // inExtensionNum
    byteBuffer.PutInt32(4); // inExtensionOffset

    byteBuffer.Flip();

    char readComment[64] = { 0 };
    byteBuffer.GetData(readComment, 64);
    std::vector<signed char> bytes(readComment, readComment + 64);

    api->FromByteArray(bytes);

    return true;
}

bool FromByteArray004(const uint8_t* data, size_t size)
{
    // 走完
    std::shared_ptr<HapInfoSegment> api = std::make_shared<HapInfoSegment>();

    ByteBuffer byteBuffer(64);
    byteBuffer.PutInt32(-1045050266); // inMagic
    byteBuffer.PutInt32(0); // inSaltSize
    byteBuffer.PutInt32(0); // inSigSize
    byteBuffer.PutInt32(1); // inFlags
    byteBuffer.PutInt64(4096); // inDataSize

    std::vector<int8_t> inSalt(32, 0);
    byteBuffer.PutData((const char*)inSalt.data(), 32);

    byteBuffer.PutInt32(1); // inExtensionNum
    byteBuffer.PutInt32(4); // inExtensionOffset

    byteBuffer.Flip();

    char readComment[64] = { 0 };
    byteBuffer.GetData(readComment, 64);
    std::vector<signed char> bytes(readComment, readComment + 64);

    api->FromByteArray(bytes);

    return true;
}

bool GetSignInfo(const uint8_t* data, size_t size)
{
    std::shared_ptr<HapInfoSegment> api = std::make_shared<HapInfoSegment>();

    api->GetSignInfo();

    return true;
}

bool GetSize(const uint8_t* data, size_t size)
{
    std::shared_ptr<HapInfoSegment> api = std::make_shared<HapInfoSegment>();

    int32_t hapInfoSegmentSize = api->GetSize();

    return hapInfoSegmentSize == 64;
}

bool SetSignInfo(const uint8_t* data, size_t size)
{
    std::shared_ptr<HapInfoSegment> api = std::make_shared<HapInfoSegment>();

    int32_t saltSize = 0;
    int32_t flags = 1;
    int64_t dataSize = 5390336;
    std::vector<int8_t> salt;
    std::vector<int8_t> sig{ 48, -126, 7, -46, 6, 9, 42, -122, 72, -122, -9, 13,
        1, 7, 2, -96, -126, 7, -61, 48, -126, 7, -65, 2, 1, 1, 49, 13, 48, 11, 6,
        9, 96, -122, 72, 1, 101, 3, 4, 2, 1, 48, 11, 6, 9, 42, -122, 72, -122, -9,
        13, 1, 7, 1, -96, -126, 6, 43, 48, -126, 1, -32, 48, -126, 1, -121, -96, 3,
        2, 1, 2, 2, 4, 85, -67, -54, 116, 48, 10, 6, 8, 42, -122, 72, -50, 61, 4, 3,
        3, 48, 85, 49, 11, 48, 9, 6, 3, 85, 4, 6, 1 };
    SignInfo signInfo(saltSize, flags, dataSize, salt, sig);
    api->SetSignInfo(signInfo);

    return true;
}

bool ToByteArray(const uint8_t* data, size_t size)
{
    std::shared_ptr<HapInfoSegment> api = std::make_shared<HapInfoSegment>();
    
    std::vector<int8_t> byteArray = api->ToByteArray();

    return byteArray.size() == 64;
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
    OHOS::GetSignInfo(data, size);
    OHOS::GetSize(data, size);
    OHOS::SetSignInfo(data, size);
    OHOS::ToByteArray(data, size);
    return 0;
}