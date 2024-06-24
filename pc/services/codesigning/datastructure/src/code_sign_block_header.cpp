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
#include "code_sign_block_header.h"

namespace OHOS {
namespace SignatureTools {

CodeSignBlockHeader::CodeSignBlockHeader()
{
    this->magic = MAGIC_NUM;
    this->version = CODE_SIGNING_VERSION;
    this->reserved = std::vector<int8_t>(RESERVED_BYTE_ARRAY_LENGTH);
}

CodeSignBlockHeader::CodeSignBlockHeader(Builder* builder)
{
    this->magic = builder->magic;
    this->version = builder->version;
    this->blockSize = builder->blockSize;
    this->segmentNum = builder->segmentNum;
    this->flags = builder->flags;
    this->reserved = builder->reserved;
}

CodeSignBlockHeader::~CodeSignBlockHeader()
{
}

void CodeSignBlockHeader::SetSegmentNum(int num)
{
    this->segmentNum = num;
}

int CodeSignBlockHeader::GetSegmentNum()
{
    return segmentNum;
}

void CodeSignBlockHeader::SetBlockSize(long long size)
{
    this->blockSize = static_cast<int>(size);
}

int CodeSignBlockHeader::GetBlockSize()
{
    return blockSize;
}

void CodeSignBlockHeader::SetFlags(int flags)
{
    this->flags = flags;
}

std::vector<int8_t> CodeSignBlockHeader::ToByteArray()
{
    ByteBuffer bf(Size());
    bf.PutInt64(magic);
    bf.PutInt32(version);
    bf.PutInt32(blockSize);
    bf.PutInt32(segmentNum);
    bf.PutInt32(flags);
    bf.PutData((const char*)reserved.data(), reserved.size());
    std::vector<int8_t> ret(bf.GetBufferPtr(), bf.GetBufferPtr() + bf.GetPosition());
    return ret;
}

CodeSignBlockHeader* CodeSignBlockHeader::FromByteArray(std::vector<signed char>& bytes)
{
    if (bytes.size() != Size()) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid size of CodeSignBlockHeader.");
        return nullptr;
    }
    ByteBuffer bf(bytes.size());
    bf.PutData((const char*)bytes.data(), bytes.size());
    bf.Flip();
    long long inMagic;
    bf.GetInt64(inMagic);
    if (inMagic != MAGIC_NUM) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid magic num of CodeSignBlockHeader.");
        return nullptr;
    }
    int inVersion;
    bf.GetInt32(inVersion);
    if (inVersion != CODE_SIGNING_VERSION) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid version of CodeSignBlockHeader.");
        return nullptr;
    }
    int inBlockSize;
    bf.GetInt32(inBlockSize);
    int inSegmentNum;
    bf.GetInt32(inSegmentNum);
    if (inSegmentNum != SEGMENT_NUM) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid segmentNum of CodeSignBlockHeader.");
        return nullptr;
    }
    int inFlags;
    bf.GetInt32(inFlags);
    if (inFlags < 0 || inFlags >(FLAG_MERKLE_TREE_INLINED + FLAG_NATIVE_LIB_INCLUDED)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid flags of CodeSignBlockHeader.");
        return nullptr;
    }
    std::vector<signed char> inReserved(RESERVED_BYTE_ARRAY_LENGTH);
    bf.GetByte(inReserved.data(), RESERVED_BYTE_ARRAY_LENGTH);
    CodeSignBlockHeader::Builder* tempVar = new CodeSignBlockHeader::Builder();
    CodeSignBlockHeader* codeSignBlockHeader = tempVar->SetMagic(inMagic)->SetVersion(inVersion)->
        SetBlockSize(inBlockSize)->SetSegmentNum(inSegmentNum)->
        SetFlags(inFlags)->SetReserved(inReserved)->Build();
    delete tempVar;
    return codeSignBlockHeader;
}

int CodeSignBlockHeader::Size()
{
    return MAGIC_BYTE_ARRAY_LENGTH + MAGIC_BYTE_LENGTH * MAGIC_BYTE_LENGTH + RESERVED_BYTE_ARRAY_LENGTH;
}

CodeSignBlockHeader::Builder* CodeSignBlockHeader::Builder::SetMagic(long long magic)
{
    this->magic = magic;
    return this;
}

CodeSignBlockHeader::Builder* CodeSignBlockHeader::Builder::SetVersion(int version)
{
    this->version = version;
    return this;
}

CodeSignBlockHeader::Builder* CodeSignBlockHeader::Builder::SetBlockSize(int blockSize)
{
    this->blockSize = blockSize;
    return this;
}

CodeSignBlockHeader::Builder* CodeSignBlockHeader::Builder::SetSegmentNum(int segmentNum)
{
    this->segmentNum = segmentNum;
    return this;
}

CodeSignBlockHeader::Builder* CodeSignBlockHeader::Builder::SetFlags(int flags)
{
    this->flags = flags;
    return this;
}

CodeSignBlockHeader::Builder* CodeSignBlockHeader::Builder::SetReserved(std::vector<signed char>& reserved)
{
    this->reserved = reserved;
    return this;
}

CodeSignBlockHeader* CodeSignBlockHeader::Builder::Build()
{
    return new CodeSignBlockHeader(this);
}

CodeSignBlockHeader::Builder::~Builder()
{
}

}
}