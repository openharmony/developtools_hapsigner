/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "fs_verity_generator.h"

namespace OHOS {
namespace SignatureTools {
const FsVerityHashAlgorithm FS_SHA256(1, "SHA-256", 256 / 8);
const FsVerityHashAlgorithm FS_SHA512(2, "SHA-512", 512 / 8);
const int8_t FsVerityGenerator::LOG_2_OF_FSVERITY_HASH_PAGE_SIZE = 12;
const uint8_t ELF_CODE_SIGN_VERSION = 0x3;
const FsVerityHashAlgorithm FsVerityGenerator::FS_VERITY_HASH_ALGORITHM = FS_SHA256;

MerkleTree* FsVerityGenerator::GenerateMerkleTree(std::istream& inputStream, long size,
    const FsVerityHashAlgorithm& fsVerityHashAlgorithm)
{
    std::unique_ptr<MerkleTreeBuilder>builder = std::make_unique<MerkleTreeBuilder>(MerkleTreeBuilder());
    builder->SetCsOffset(csOffset);
    return builder->GenerateMerkleTree(inputStream, size, fsVerityHashAlgorithm);
}

bool FsVerityGenerator::GenerateFsVerityDigest(std::istream& inputStream, long size, int flags)
{
    MerkleTree* merkleTree = GenerateMerkleTree(inputStream, size, FS_SHA256);
    if (merkleTree == nullptr) {
        return false;
    }
    std::shared_ptr<MerkleTree> merkleTree_ptr(merkleTree);
    // sign size is 0,
    std::unique_ptr<FsVerityDescriptor::Builder> builder = std::make_unique<FsVerityDescriptor::Builder>();
    builder->SetFileSize(size)
        .SetHashAlgorithm(FS_SHA256.GetId())
        .SetLog2BlockSize(LOG_2_OF_FSVERITY_HASH_PAGE_SIZE)
        .SetSaltSize((uint8_t)GetSaltSize())
        .SetSalt(salt)
        .SetRawRootHash(merkleTree_ptr->rootHash)
        .SetFlags(flags)
        .SetCsVersion(ELF_CODE_SIGN_VERSION);
    std::vector<int8_t> fsVerityDescriptor;
    builder->Build().GetByteForGenerateDigest(fsVerityDescriptor);
    DigestUtils digestUtils(HASH_SHA256);
    std::stringstream ss;
    for (const auto& elem : fsVerityDescriptor) {
        ss << elem;
    }
    digestUtils.AddData(ss.str());
    std::string result = digestUtils.Result(DigestUtils::Type::BINARY);
    for (long i = 0; i < result.size(); i++) {
        descriptorDigest.push_back(result[i]);
    }
    FsVerityDigest::GetFsVerityDigest(FS_SHA256.GetId(), descriptorDigest, fsVerityDigest);
    treeBytes = merkleTree_ptr->tree;
    rootHash = merkleTree_ptr->rootHash;
    return true;
}
} // namespace SignatureTools
} // namespace OHOS