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
#include "fs_verity_info_segment.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool FromByteArray001(const uint8_t* data, size_t size)
{
    // 走第一个分支:size不相等
    std::shared_ptr<FsVerityInfoSegment> api = std::make_shared<FsVerityInfoSegment>();

    std::vector<int8_t> bytes;
    api->FromByteArray(bytes);

    return true;
}

bool FromByteArray002(const uint8_t* data, size_t size)
{
    // 走第二个分支:inMagic 不相等
    std::shared_ptr<FsVerityInfoSegment> api = std::make_shared<FsVerityInfoSegment>();

    ByteBuffer byteBuffer(64);
    byteBuffer.PutInt32(0);  // inMagic
    byteBuffer.Flip();

    char readComment[64] = { 0 };
    byteBuffer.GetData(readComment, 64);
    std::vector<signed char> bytes(readComment, readComment + 64);
    
    api->FromByteArray(bytes);

    return true;
}

bool FromByteArray003(const uint8_t* data, size_t size)
{
    // 走第三个分支:inVersion 不相等
    std::shared_ptr<FsVerityInfoSegment> api = std::make_shared<FsVerityInfoSegment>();

    ByteBuffer byteBuffer(64);
    byteBuffer.PutInt32(506999211);  // inMagic
    byteBuffer.PutUInt8(0);  // inVersion
    byteBuffer.Flip();

    char readComment[64] = { 0 };
    byteBuffer.GetData(readComment, 64);
    std::vector<signed char> bytes(readComment, readComment + 64);
    
    api->FromByteArray(bytes);

    return true;
}

bool FromByteArray004(const uint8_t* data, size_t size)
{
    // 走第四个分支:inHashAlgorithm 不相等
    std::shared_ptr<FsVerityInfoSegment> api = std::make_shared<FsVerityInfoSegment>();

    ByteBuffer byteBuffer(64);
    byteBuffer.PutInt32(506999211);  // inMagic
    byteBuffer.PutUInt8(1);  // inVersion
    byteBuffer.PutUInt8(0);  // inHashAlgorithm
    byteBuffer.Flip();

    char readComment[64] = { 0 };
    byteBuffer.GetData(readComment, 64);
    std::vector<signed char> bytes(readComment, readComment + 64);
    
    api->FromByteArray(bytes);

    return true;
}

bool FromByteArray005(const uint8_t* data, size_t size)
{
    // 走第五个分支:inLog2BlockSize 不相等
    std::shared_ptr<FsVerityInfoSegment> api = std::make_shared<FsVerityInfoSegment>();

    ByteBuffer byteBuffer(64);
    byteBuffer.PutInt32(506999211);  // inMagic
    byteBuffer.PutUInt8(1);  // inVersion
    byteBuffer.PutUInt8(1);  // inHashAlgorithm
    byteBuffer.PutUInt8(0);  // inLog2BlockSize
    byteBuffer.Flip();

    char readComment[64] = { 0 };
    byteBuffer.GetData(readComment, 64);
    std::vector<signed char> bytes(readComment, readComment + 64);
    
    api->FromByteArray(bytes);

    return true;
}

bool FromByteArray006(const uint8_t* data, size_t size)
{
    // 走完
    std::shared_ptr<FsVerityInfoSegment> api = std::make_shared<FsVerityInfoSegment>();

    ByteBuffer byteBuffer(64);
    byteBuffer.PutInt32(506999211);  // inMagic
    byteBuffer.PutUInt8(1);  // inVersion
    byteBuffer.PutUInt8(1);  // inHashAlgorithm
    byteBuffer.PutUInt8(12);  // inLog2BlockSize
    byteBuffer.Flip();

    char readComment[64] = { 0 };
    byteBuffer.GetData(readComment, 64);
    std::vector<signed char> bytes(readComment, readComment + 64);
    
    api->FromByteArray(bytes);

    return true;
}

bool FromByteArray(const uint8_t* data, size_t size)
{
    std::shared_ptr<FsVerityInfoSegment> api = std::make_shared<FsVerityInfoSegment>();

    std::vector<int8_t> bytes{ 12, 45, 58, -12, 38, 29, 12, 45, 58, -12, 38, 29, 12, 45,
        58, -12, 38, 29, 12, 45, 58, -12, 38, 29, 12, 45, 58, -12, 38, 29, 13, 26, 12, 45,
        58, -12, 38, 29, 12, 45, 58, -12, 38, 29, 12, 45, 58, -12, 38, 29, 12, 45, 58, -12,
        38, 29, 12, 45, 58, -12, 38, 29, 13, 26 };
    api->FromByteArray(bytes);

    return true;
}

bool Size(const uint8_t* data, size_t size)
{
    std::shared_ptr<FsVerityInfoSegment> api = std::make_shared<FsVerityInfoSegment>();
    
    int fsVerityInfoSegmentSize = api->Size();

    return fsVerityInfoSegmentSize == 64;
}

bool ToByteArray(const uint8_t* data, size_t size)
{
    std::shared_ptr<FsVerityInfoSegment> api = std::make_shared<FsVerityInfoSegment>();

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
    OHOS::FromByteArray005(data, size);
    OHOS::FromByteArray006(data, size);
    OHOS::FromByteArray(data, size);
    OHOS::Size(data, size);
    OHOS::ToByteArray(data, size);
    return 0;
}