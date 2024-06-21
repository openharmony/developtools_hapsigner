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
#include <fstream>
#include "fs_verity_generator.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool GenerateMerkleTree(const uint8_t* data, size_t size)
{
    const FsVerityHashAlgorithm FS_SHA256(1, "SHA-256", 256 / 8);
    std::ifstream inputStream("./codeSigning/entry-default-signed-so.hap", std::ios::binary);
    FsVerityGenerator fsVerityGenerator;

    MerkleTree* merkleTree = fsVerityGenerator.GenerateMerkleTree(inputStream, 69632, FS_SHA256);

    return merkleTree != nullptr;
}

bool GenerateFsVerityDigest(const uint8_t* data, size_t size)
{
    std::ifstream inputStream("./codeSigning/entry-default-signed-so.hap", std::ios::binary);
    FsVerityGenerator fsVerityGenerator;

    fsVerityGenerator.GenerateFsVerityDigest(inputStream, 69632, 1400832);

    return fsVerityGenerator.GetFsVerityDigest()[0] != 0;
}

bool GetFsVerityDigest(const uint8_t* data, size_t size)
{
    std::ifstream inputStream("./codeSigning/entry-default-signed-so.hap", std::ios::binary);
    FsVerityGenerator fsVerityGenerator;

    fsVerityGenerator.GenerateFsVerityDigest(inputStream, 69632, 1400832);
    std::vector<int8_t> digest = fsVerityGenerator.GetFsVerityDigest();

    return digest[0] != 0;
}

bool GetTreeBytes(const uint8_t* data, size_t size)
{
    std::ifstream inputStream("./codeSigning/entry-default-signed-so.hap", std::ios::binary);
    FsVerityGenerator fsVerityGenerator;

    fsVerityGenerator.GenerateFsVerityDigest(inputStream, 69632, 1400832);
    std::vector<int8_t> treeBytes = fsVerityGenerator.GetTreeBytes();

    return treeBytes[0] != 0;
}

bool GetRootHash(const uint8_t* data, size_t size)
{
    std::ifstream inputStream("./codeSigning/entry-default-signed-so.hap", std::ios::binary);
    FsVerityGenerator fsVerityGenerator;

    fsVerityGenerator.GenerateFsVerityDigest(inputStream, 69632, 1400832);
    std::vector<int8_t> rootHash = fsVerityGenerator.GetRootHash();

    return rootHash[0] != 0;
}

bool GetSaltSize(const uint8_t* data, size_t size)
{
    std::ifstream inputStream("./codeSigning/entry-default-signed-so.hap", std::ios::binary);
    FsVerityGenerator fsVerityGenerator;

    fsVerityGenerator.GenerateFsVerityDigest(inputStream, 69632, 1400832);
    int saltSize = fsVerityGenerator.GetSaltSize();

    return saltSize == 0;
}

bool GetFsVerityHashAlgorithm(const uint8_t* data, size_t size)
{
    std::ifstream inputStream("./codeSigning/entry-default-signed-so.hap", std::ios::binary);
    FsVerityGenerator fsVerityGenerator;

    fsVerityGenerator.GenerateFsVerityDigest(inputStream, 69632, 1400832);
    uint8_t algorithm = fsVerityGenerator.GetFsVerityHashAlgorithm();

    return algorithm != 0;
}

bool GetLog2BlockSize(const uint8_t* data, size_t size)
{
    std::ifstream inputStream("./codeSigning/entry-default-signed-so.hap", std::ios::binary);
    FsVerityGenerator fsVerityGenerator;

    fsVerityGenerator.GenerateFsVerityDigest(inputStream, 69632, 1400832);
    uint8_t blockSize = fsVerityGenerator.GetLog2BlockSize();

    return blockSize != 0;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GenerateMerkleTree(data, size);
    OHOS::GenerateFsVerityDigest(data, size);
    OHOS::GetFsVerityDigest(data, size);
    OHOS::GetTreeBytes(data, size);
    OHOS::GetRootHash(data, size);
    OHOS::GetSaltSize(data, size);
    OHOS::GetFsVerityHashAlgorithm(data, size);
    OHOS::GetLog2BlockSize(data, size);
    return 0;
}