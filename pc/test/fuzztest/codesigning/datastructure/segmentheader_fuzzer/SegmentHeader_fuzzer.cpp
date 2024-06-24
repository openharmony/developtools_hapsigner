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
#include "segment_header.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool GetSegmentOffset(const uint8_t* data, size_t size)
{
    std::shared_ptr<SegmentHeader> api = std::make_shared<SegmentHeader>();

    int32_t segmentOffset = api->GetSegmentOffset();

    return segmentOffset == 0;
}

bool FromByteArray001(const uint8_t* data, size_t size)
{
    SegmentHeader segmentHeader(1, 1, 8);
    std::vector<int8_t> arr = { 1, 1, 1, 1 };
    std::unique_ptr<SegmentHeader> ptr = segmentHeader.FromByteArray(arr);

    return arr.size() == 4;
}

bool FromByteArray002(const uint8_t* data, size_t size)
{
    SegmentHeader segmentHeader(0, 1, 8);
    std::vector<int8_t> arr = segmentHeader.ToByteArray();
    std::unique_ptr<SegmentHeader> ptr = segmentHeader.FromByteArray(arr);

    return arr.size() == 0;
}

bool FromByteArray003(const uint8_t* data, size_t size)
{
    SegmentHeader segmentHeader1;
    SegmentHeader segmentHeader(1, 1, -1);
    std::vector<int8_t> arr = segmentHeader.ToByteArray();
    std::unique_ptr<SegmentHeader> ptr = segmentHeader.FromByteArray(arr);

    return arr.size() == 0;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetSegmentOffset(data, size);
    OHOS::FromByteArray001(data, size);
    OHOS::FromByteArray002(data, size);
    OHOS::FromByteArray003(data, size);
    return 0;
}