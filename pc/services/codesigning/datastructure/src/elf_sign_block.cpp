/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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

#include "elf_sign_block.h"

using namespace OHOS::SignatureTools;

const int32_t ElfSignBlock::PAGE_SIZE_4K = 4096;
const int32_t ElfSignBlock::MERKLE_TREE_INLINED = 0x2;

ElfSignBlock::ElfSignBlock()
{
    this->type = MERKLE_TREE_INLINED;
}

ElfSignBlock::ElfSignBlock(int32_t paddingSize, std::vector<int8_t> merkleTreeData,
    FsVerityDescriptorWithSign descriptorWithSign)
{
    std::vector<int8_t> inMerkleTreeData;
    if (!merkleTreeData.empty()) {
        inMerkleTreeData = merkleTreeData;
    }
    this->treeLength = paddingSize + inMerkleTreeData.size();
    this->merkleTreeWithPadding.resize(this->treeLength);
    std::copy(inMerkleTreeData.begin(), inMerkleTreeData.end(), this->merkleTreeWithPadding.begin() + paddingSize);
    this->descriptorWithSign = descriptorWithSign;
}

ElfSignBlock::ElfSignBlock(int32_t type, int32_t treeLength, std::vector<int8_t> merkleTreeWithPadding,
    FsVerityDescriptorWithSign descriptorWithSign)
{
    this->type = type;
    this->treeLength = treeLength;
    this->merkleTreeWithPadding = merkleTreeWithPadding;
    this->descriptorWithSign = descriptorWithSign;
}

int32_t ElfSignBlock::Size()
{
    return FsVerityDescriptorWithSign::INTEGER_BYTES * 2 + merkleTreeWithPadding.size() + descriptorWithSign.Size();
}

std::vector<int8_t> ElfSignBlock::GetMerkleTreeWithPadding()
{
    return merkleTreeWithPadding;
}

int64_t ElfSignBlock::GetDataSize()
{
    return descriptorWithSign.GetFsVerityDescriptor().GetFileSize();
}

int64_t ElfSignBlock::GetTreeOffset()
{
    return descriptorWithSign.GetFsVerityDescriptor().GetMerkleTreeOffset();
}

std::vector<int8_t> ElfSignBlock::GetSignature()
{
    return descriptorWithSign.GetSignature();
}

std::vector<int8_t> ElfSignBlock::ToByteArray()
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(Size());
    bf->PutInt32(type);
    bf->PutInt32(merkleTreeWithPadding.size());
    bf->PutData((char*)merkleTreeWithPadding.data(), merkleTreeWithPadding.size());
    std::vector<int8_t> descriptorWithSignArr = descriptorWithSign.ToByteArray();
    bf->PutData((char*)descriptorWithSignArr.data(), descriptorWithSignArr.size());
    bf->Flip();
    std::vector<int8_t> ret(bf->GetBufferPtr(), bf->GetBufferPtr() + bf->GetLimit());
    return ret;
}

bool ElfSignBlock::FromByteArray(std::vector<int8_t>& bytes, ElfSignBlock& elfSignBlock)
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(bytes.size());
    bf->PutData((char*)bytes.data(), bytes.size());
    bf->Flip();
    int32_t inTreeType = 0;
    bf->GetInt32(inTreeType);
    if (MERKLE_TREE_INLINED != inTreeType) {
        SIGNATURE_TOOLS_LOGE("Invalid merkle tree type of ElfSignBlock\n");
        return false;
    }
    int32_t inTreeLength = 0;
    bf->GetInt32(inTreeLength);
    std::vector<int8_t> treeWithPadding(inTreeLength);
    bf->GetData((char*)treeWithPadding.data(), treeWithPadding.size());
    int32_t inFsdType = 0;
    bf->GetInt32(inFsdType);
    if (FsVerityDescriptor::FS_VERITY_DESCRIPTOR_TYPE != inFsdType) {
        SIGNATURE_TOOLS_LOGE("Invalid fs-verify descriptor type of ElfSignBlock\n");
        return false;
    }
    int32_t inFsdLength = 0;
    bf->GetInt32(inFsdLength);
    if (bytes.size() != FsVerityDescriptorWithSign::INTEGER_BYTES * 2 + inTreeLength +
        FsVerityDescriptorWithSign::INTEGER_BYTES * 2 + inFsdLength) {
        SIGNATURE_TOOLS_LOGE("Invalid fs-verify descriptor with signature length of ElfSignBlock\n");
        return false;
    }
    std::vector<int8_t> fsdArray(FsVerityDescriptor::DESCRIPTOR_SIZE);
    bf->GetData((char*)fsdArray.data(), fsdArray.size());
    FsVerityDescriptor fsd = FsVerityDescriptor::FromByteArray(fsdArray);
    if (inFsdLength != fsd.GetSignSize() + FsVerityDescriptor::DESCRIPTOR_SIZE) {
        SIGNATURE_TOOLS_LOGE("Invalid sign size of ElfSignBlock\n");
        return false;
    }
    std::vector<int8_t> inSignature(inFsdLength - FsVerityDescriptor::DESCRIPTOR_SIZE);
    bf->GetData((char*)inSignature.data(), inSignature.size());
    FsVerityDescriptorWithSign fsVerityDescriptorWithSign(inFsdType, inFsdLength, fsd, inSignature);
    elfSignBlock.type = inTreeType;
    elfSignBlock.treeLength = inTreeLength;
    elfSignBlock.merkleTreeWithPadding = treeWithPadding;
    elfSignBlock.descriptorWithSign = fsVerityDescriptorWithSign;
    return true;
}

int32_t ElfSignBlock::ComputeMerkleTreePaddingLength(int64_t signBlockOffset)
{
    return (int32_t) (PAGE_SIZE_4K - (signBlockOffset + FsVerityDescriptorWithSign::INTEGER_BYTES * 2)
        % PAGE_SIZE_4K) % PAGE_SIZE_4K;
}