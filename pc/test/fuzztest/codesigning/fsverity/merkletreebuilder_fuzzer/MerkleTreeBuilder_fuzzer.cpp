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
#include "merkle_tree_builder.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool GenerateMerkleTree001(const uint8_t* data, size_t size)
{
    const FsVerityHashAlgorithm SHA256((char)1, "SHA-256", 256 / 8);
    std::ifstream inputStream("./codeSigning/entry-default-signed-so.hap", std::ios::binary);

    MerkleTreeBuilder builder;
    MerkleTree* merkleTree = builder.GenerateMerkleTree(inputStream, 69632, SHA256);

    return merkleTree != nullptr;
}

bool GenerateMerkleTree002(const uint8_t* data, size_t size)
{
    const FsVerityHashAlgorithm SHA256((char)1, "SHA-256", 256 / 8);
    std::ifstream inputStream("./codeSigning/entry-default-signed-so.hap", std::ios::binary);

    MerkleTreeBuilder builder;
    MerkleTree* merkleTree = builder.GenerateMerkleTree(inputStream, 4095, SHA256);

    return merkleTree != nullptr;
}

bool GenerateMerkleTree003(const uint8_t* data, size_t size)
{
    const FsVerityHashAlgorithm SHA256((char)1, "SHA-256", 256 / 8);
    std::ifstream inputStream("./codeSigning/entry-default-signed-so.hap", std::ios::binary);

    MerkleTreeBuilder builder;
    MerkleTree* merkleTree = builder.GenerateMerkleTree(inputStream, 0, SHA256);

    return merkleTree != nullptr;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GenerateMerkleTree001(data, size);
    OHOS::GenerateMerkleTree002(data, size);
    OHOS::GenerateMerkleTree003(data, size);
    return 0;
}