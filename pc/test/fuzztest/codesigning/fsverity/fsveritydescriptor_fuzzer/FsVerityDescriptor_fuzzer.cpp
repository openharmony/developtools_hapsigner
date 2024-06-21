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
#include "fs_verity_descriptor.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool Build(const uint8_t* data, size_t size)
{
    std::vector<int8_t> salt = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();

    return fsVerityDescriptor.GetFileSize() == 32;
}

bool GetFileSize(const uint8_t* data, size_t size)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();

     return fsVerityDescriptor.GetFileSize() == 32;
}

bool GetMerkleTreeOffset(const uint8_t* data, size_t size)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();

    return fsVerityDescriptor.GetMerkleTreeOffset() == 0;
}

bool GetSignSize(const uint8_t* data, size_t size)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();

    return fsVerityDescriptor.GetSignSize() == 32;
}

bool ToByteArray001(const uint8_t* data, size_t size)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();
    std::vector<int8_t> arr = fsVerityDescriptor.ToByteArray();

    return fsVerityDescriptor.GetSignSize() == 32;
}

bool ToByteArray002(const uint8_t* data, size_t size)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)64)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();
    std::vector<int8_t> arr = fsVerityDescriptor.ToByteArray();
    int32_t sizet = arr.size();

    return sizet == 0;
}

bool FromByteArray001(const uint8_t* data, size_t size)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();
    std::vector<int8_t> arr = fsVerityDescriptor.ToByteArray();
    FsVerityDescriptor fromArr = FsVerityDescriptor::FromByteArray(arr);

    return fromArr.GetFileSize() == 32;
}

bool FromByteArray002(const uint8_t* data, size_t size)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();
    std::vector<int8_t> arr = fsVerityDescriptor.ToByteArray();
    arr[0] = 2;
    FsVerityDescriptor fromArr = FsVerityDescriptor::FromByteArray(arr);

    return fromArr.GetFileSize() == 0;
}

bool FromByteArray003(const uint8_t* data, size_t size)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(4097)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();
    std::vector<int8_t> arr = fsVerityDescriptor.ToByteArray();
    FsVerityDescriptor fromArr = FsVerityDescriptor::FromByteArray(arr);

    return fromArr.GetFileSize() == 32;
}

bool GetByteForGenerateDigest001(const uint8_t* data, size_t size)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();
    std::vector<int8_t> bytes = fsVerityDescriptor.GetByteForGenerateDigest();

    return fsVerityDescriptor.GetSignSize() == 32;
}

bool GetByteForGenerateDigest002(const uint8_t* data, size_t size)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)64)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();
    std::vector<int8_t> bytes = fsVerityDescriptor.GetByteForGenerateDigest();
    int32_t sizet = bytes.size();

    return sizet == 0;
}

bool WriteBytesWithSize(const uint8_t* data, size_t size)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);
    FsVerityDescriptor fsVerityDescriptor = builder.Build();

    std::unique_ptr<ByteBuffer> buffer = std::make_unique<ByteBuffer>(64);
    std::vector<int8_t> src = { 1, 1, 1, 1, 1, 1, 1, 1 };
    fsVerityDescriptor.WriteBytesWithSize(buffer.get(), src, 4);
    int32_t sizet = src.size();

    return sizet == 8;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Build(data, size);
    OHOS::GetFileSize(data, size);
    OHOS::GetMerkleTreeOffset(data, size);
    OHOS::GetSignSize(data, size);
    OHOS::ToByteArray001(data, size);
    OHOS::ToByteArray002(data, size);
    OHOS::FromByteArray001(data, size);
    OHOS::FromByteArray002(data, size);
    OHOS::FromByteArray003(data, size);
    OHOS::GetByteForGenerateDigest001(data, size);
    OHOS::GetByteForGenerateDigest002(data, size);
    OHOS::WriteBytesWithSize(data, size);
    return 0;
}