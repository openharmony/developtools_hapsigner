/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include "merkle_tree_extension.h"

namespace OHOS {
namespace SignatureTools {

const int32_t MerkleTreeExtension::MERKLE_TREE_INLINED = 0x1;
const int32_t MerkleTreeExtension::MERKLE_TREE_EXTENSION_DATA_SIZE = 80;
const int32_t MerkleTreeExtension::ROOT_HASH_SIZE = 64;
const int32_t MerkleTreeExtension::PAGE_SIZE_4K = 4096;

MerkleTreeExtension::MerkleTreeExtension()
    : Extension(MERKLE_TREE_INLINED, MERKLE_TREE_EXTENSION_DATA_SIZE)
{
    this->merkleTreeSize = 0;
    this->merkleTreeOffset = 0;
}

MerkleTreeExtension::MerkleTreeExtension(int64_t merkleTreeSize, int64_t merkleTreeOffset, std::vector<int8_t> rootHash)
    : Extension(MERKLE_TREE_INLINED, MERKLE_TREE_EXTENSION_DATA_SIZE)
{
    this->merkleTreeSize = merkleTreeSize;
    this->merkleTreeOffset = merkleTreeOffset;
    this->rootHash = rootHash;
}

MerkleTreeExtension::~MerkleTreeExtension()
{
}

int32_t MerkleTreeExtension::GetSize()
{
    return Extension::EXTENSION_HEADER_SIZE + MERKLE_TREE_EXTENSION_DATA_SIZE;
}

int64_t MerkleTreeExtension::GetMerkleTreeSize()
{
    return merkleTreeSize;
}

int64_t MerkleTreeExtension::GetMerkleTreeOffset()
{
    return merkleTreeOffset;
}

void MerkleTreeExtension::SetMerkleTreeOffset(int64_t offset)
{
    this->merkleTreeOffset = offset;
}

std::vector<int8_t> MerkleTreeExtension::ToByteArray()
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(
        Extension::EXTENSION_HEADER_SIZE + MERKLE_TREE_EXTENSION_DATA_SIZE));
    std::vector<int8_t> extByteArr = Extension::ToByteArray();
    bf->PutData(extByteArr.data(), extByteArr.size());
    bf->PutInt64(this->merkleTreeSize);
    bf->PutInt64(this->merkleTreeOffset);
    bf->PutData(this->rootHash.data(), this->rootHash.size());
    std::vector<int8_t> ret(bf->GetBufferPtr(), bf->GetBufferPtr() + bf->GetCapacity());
    return ret;
}

std::string MerkleTreeExtension::ToString()
{
    return "";
}

MerkleTreeExtension* MerkleTreeExtension::FromByteArray(std::vector<int8_t> bytes)
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(bytes.size()));
    bf->PutData(bytes.data(), bytes.size());
    bf->Flip();
    long long inMerkleTreeSize = 0;
    bf->GetInt64(inMerkleTreeSize);
    if (inMerkleTreeSize % PAGE_SIZE_4K != 0) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "merkleTreeSize is not a multiple of 4096");
        return nullptr;
    }
    long long inMerkleTreeOffset = 0;
    bf->GetInt64(inMerkleTreeOffset);
    if (inMerkleTreeOffset % PAGE_SIZE_4K != 0) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "merkleTreeOffset is not a aligned to 4096");
        return nullptr;
    }
    std::vector<int8_t> inRootHash(ROOT_HASH_SIZE);
    bf->GetByte(inRootHash.data(), inRootHash.size());
    return new MerkleTreeExtension(inMerkleTreeSize, inMerkleTreeOffset, inRootHash);
}

}
}