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
#include "code_sign_block.h"
#include "merkle_tree_extension.h"

namespace OHOS {
namespace SignatureTools {

const long CodeSignBlock::PAGE_SIZE_4K = 4096;
const int CodeSignBlock::SEGMENT_HEADER_COUNT = 3;

CodeSignBlock::CodeSignBlock()
{
}

CodeSignBlock::~CodeSignBlock()
{
}

void CodeSignBlock::AddOneMerkleTree(const std::string& key, std::vector<int8_t>& merkleTree)
{
    if (merkleTreeMap.find(key) == merkleTreeMap.end()) {
        if (key.empty()) {
            return;
        }
        if (merkleTree.empty()) {
            merkleTreeMap.insert(std::make_pair(key, std::vector<int8_t>(0)));
        } else {
            merkleTreeMap.insert(std::make_pair(key, merkleTree));
        }
    }
}

std::vector<int8_t> CodeSignBlock::GetOneMerkleTreeByFileName(const std::string& key)
{
    if (key.empty()) {
        return std::vector<int8_t>();
    }
    return this->merkleTreeMap[key];
}

void CodeSignBlock::SetCodeSignBlockFlag()
{
    int flags = CodeSignBlockHeader::FLAG_MERKLE_TREE_INLINED;
    if (this->nativeLibInfoSegment.GetSectionNum() != 0) {
        flags |= CodeSignBlockHeader::FLAG_NATIVE_LIB_INCLUDED;
    }
    this->codeSignBlockHeader.SetFlags(flags);
}

void CodeSignBlock::SetSegmentNum()
{
    this->codeSignBlockHeader.SetSegmentNum(static_cast<int>(segmentHeaderList.size()));
}

void CodeSignBlock::AddToSegmentList(SegmentHeader sh)
{
    this->segmentHeaderList.push_back(sh);
}

std::vector<SegmentHeader>& CodeSignBlock::GetSegmentHeaderList()
{
    return segmentHeaderList;
}

void CodeSignBlock::SetSegmentHeaders()
{
    // fs-verity info segment
    SegmentHeader tempVar(SegmentHeader::CSB_FSVERITY_INFO_SEG, FsVerityInfoSegment::FS_VERITY_INFO_SEGMENT_SIZE);
    segmentHeaderList.push_back(tempVar);
    // hap info segment
    SegmentHeader tempVar2(SegmentHeader::CSB_HAP_META_SEG, this->hapInfoSegment.GetSize());
    segmentHeaderList.push_back(tempVar2);
    // native lib info segment
    SegmentHeader tempVar3(SegmentHeader::CSB_NATIVE_LIB_INFO_SEG, this->nativeLibInfoSegment.Size());
    segmentHeaderList.push_back(tempVar3);
}

CodeSignBlockHeader& CodeSignBlock::GetCodeSignBlockHeader()
{
    return codeSignBlockHeader;
}

void CodeSignBlock::SetCodeSignBlockHeader(CodeSignBlockHeader& csbHeader)
{
    codeSignBlockHeader = csbHeader;
}

void CodeSignBlock::SetFsVerityInfoSegment(FsVerityInfoSegment& fsVeritySeg)
{
    this->fsVerityInfoSegment = fsVeritySeg;
}

FsVerityInfoSegment& CodeSignBlock::GetFsVerityInfoSegment()
{
    return fsVerityInfoSegment;
}

HapInfoSegment& CodeSignBlock::GetHapInfoSegment()
{
    return hapInfoSegment;
}

void CodeSignBlock::SetHapInfoSegment(HapInfoSegment& hapSeg)
{
    this->hapInfoSegment = hapSeg;
}

NativeLibInfoSegment& CodeSignBlock::GetSoInfoSegment()
{
    return nativeLibInfoSegment;
}

void CodeSignBlock::SetSoInfoSegment(NativeLibInfoSegment soSeg)
{
    this->nativeLibInfoSegment = soSeg;
}

std::vector<int8_t> CodeSignBlock::ToByteArray()
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>
        (ByteBuffer(this->codeSignBlockHeader.GetBlockSize()));
    bf->PutData(this->codeSignBlockHeader.ToByteArray().data(),
        this->codeSignBlockHeader.ToByteArray().size());
    for (auto sh : this->segmentHeaderList) {
        bf->PutData(sh.ToByteArray().data(), sh.ToByteArray().size());
    }
    bf->PutData(this->zeroPadding.data(), this->zeroPadding.size());
    // Hap merkle tree
    bf->PutData(merkleTreeMap["Hap"].data(), merkleTreeMap["Hap"].size());
    bf->PutData(this->fsVerityInfoSegment.ToByteArray().data(), this->fsVerityInfoSegment.ToByteArray().size());
    bf->PutData(this->hapInfoSegment.ToByteArray().data(), this->hapInfoSegment.ToByteArray().size());
    bf->PutData(this->nativeLibInfoSegment.ToByteArray().data(),
        this->nativeLibInfoSegment.ToByteArray().size());
    std::vector<int8_t> ret(bf->GetBufferPtr(), bf->GetBufferPtr() + bf->GetPosition());
    return ret;
}

void CodeSignBlock::ComputeSegmentOffset()
{
    // 1) the first segment is placed after merkle tree
    int segmentOffset = CodeSignBlockHeader::Size()
        + this->segmentHeaderList.size() * SegmentHeader::SEGMENT_HEADER_LENGTH
        + this->zeroPadding.size() + this->GetOneMerkleTreeByFileName("Hap").size();
    for (int i = 0; i < segmentHeaderList.size(); i++) {
        segmentHeaderList[i].SetSegmentOffset(static_cast<int32_t>(segmentOffset));
        segmentOffset += segmentHeaderList[i].GetSegmentSize();
    }
}

long long CodeSignBlock::ComputeMerkleTreeOffset(long long codeSignBlockOffset)
{
    long long sizeWithoutMerkleTree = CodeSignBlockHeader::Size()
        + SEGMENT_HEADER_COUNT * SegmentHeader::SEGMENT_HEADER_LENGTH;
    // add code sign block offset while computing align position for merkle tree
    long long residual = (codeSignBlockOffset + sizeWithoutMerkleTree) % PAGE_SIZE_4K;
    if (residual == 0) {
        this->zeroPadding = std::vector<int8_t>(0);
    } else {
        this->zeroPadding = std::vector<int8_t>(static_cast<int>(PAGE_SIZE_4K - residual));
    }
    return codeSignBlockOffset + sizeWithoutMerkleTree + zeroPadding.size();
}

std::vector<int8_t> CodeSignBlock::GenerateCodeSignBlockByte(long long fsvTreeOffset)
{
    // 1) compute overall block size without merkle tree
    int64_t csbSize = CodeSignBlockHeader::Size()
        + static_cast<long long>(this->segmentHeaderList.size()) * SegmentHeader::SEGMENT_HEADER_LENGTH
        + this->zeroPadding.size()
        + this->GetOneMerkleTreeByFileName("Hap").size()
        + this->fsVerityInfoSegment.Size()
        + this->hapInfoSegment.GetSize()
        + this->nativeLibInfoSegment.Size();
    Extension* ext = this->hapInfoSegment.GetSignInfo().GetExtensionByType(MerkleTreeExtension::MERKLE_TREE_INLINED);
    if (ext != nullptr) {
        MerkleTreeExtension* merkleTreeExtension = (MerkleTreeExtension*)(ext);
        merkleTreeExtension->SetMerkleTreeOffset(fsvTreeOffset);
    }
    this->codeSignBlockHeader.SetBlockSize(csbSize);
    // 2) generate byte array of complete code sign block
    return ToByteArray();
}

std::string CodeSignBlock::ToString()
{
    return "";
}

}
}