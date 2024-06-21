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
#include "fs_verity_descriptor_with_sign.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool Size001(const uint8_t* data, size_t size)
{
    FsVerityDescriptorWithSign descriptor;
    int32_t sizet = descriptor.Size();

    return sizet == 0;
}

bool Size002(const uint8_t* data, size_t size)
{
    FsVerityDescriptor fsVerityDescriptor;
    std::vector<int8_t> signature = { 1, 1, 1, 1 };
    FsVerityDescriptorWithSign descriptor(fsVerityDescriptor, signature);
    int32_t sizet = descriptor.Size();

    return sizet == 0;
}

bool Size003(const uint8_t* data, size_t size)
{
    FsVerityDescriptor fsVerityDescriptor;
    std::vector<int8_t> signature;
    FsVerityDescriptorWithSign descriptor(fsVerityDescriptor, signature);
    int32_t sizet = descriptor.Size();

    return sizet == 0;
}

bool ToByteArray(const uint8_t* data, size_t size)
{
    FsVerityDescriptor fsVerityDescriptor;
    std::vector<int8_t> signature = { 1, 1, 1, 1 };
    int32_t type = 1;
    int32_t length = 0;
    FsVerityDescriptorWithSign descriptor(type, length, fsVerityDescriptor, signature);
    std::vector<int8_t> bytes = descriptor.ToByteArray();
    int32_t sizet = bytes.size();

    return sizet == 0;
}

bool GetFsVerityDescriptor(const uint8_t* data, size_t size)
{
    FsVerityDescriptor fsVerityDescriptor;
    std::vector<int8_t> signature = { 1, 1, 1, 1 };
    int32_t type = 1;
    int32_t length = 0;
    FsVerityDescriptorWithSign descriptor(type, length, fsVerityDescriptor, signature);
    FsVerityDescriptor getObj = descriptor.GetFsVerityDescriptor();
    int32_t sizet = getObj.GetSignSize();

    return sizet == 0;
}

bool GetSignature(const uint8_t* data, size_t size)
{
    FsVerityDescriptor fsVerityDescriptor;
    std::vector<int8_t> signature = { 1, 1, 1, 1 };
    int32_t type = 1;
    int32_t length = 0;
    FsVerityDescriptorWithSign descriptor(type, length, fsVerityDescriptor, signature);
    std::vector<int8_t> sig = descriptor.GetSignature();
    int32_t sizet = sig.size();

    return sizet == 4;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Size001(data, size);
    OHOS::Size002(data, size);
    OHOS::Size003(data, size);
    OHOS::ToByteArray(data, size);
    OHOS::GetFsVerityDescriptor(data, size);
    OHOS::GetSignature(data, size);
    return 0;
}