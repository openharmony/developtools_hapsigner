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
#include "fs_verity_info_segment.h"

namespace OHOS {
namespace SignatureTools {

const int FsVerityInfoSegment::MAGIC = static_cast<int>((0x1E38 << 16) + (0x31AB));
const int FsVerityInfoSegment::RESERVED_BYTE_ARRAY_LENGTH = 57;

FsVerityInfoSegment::FsVerityInfoSegment()
{
    this->magic = MAGIC;
    this->reserved = std::vector<int8_t>(RESERVED_BYTE_ARRAY_LENGTH);
}

FsVerityInfoSegment::FsVerityInfoSegment(signed char version, signed char hashAlgorithm, signed char log2BlockSize)
{
    this->magic = MAGIC;
    this->version = version;
    this->hashAlgorithm = hashAlgorithm;
    this->log2BlockSize = log2BlockSize;
    this->reserved = std::vector<int8_t>(RESERVED_BYTE_ARRAY_LENGTH);
}

FsVerityInfoSegment::FsVerityInfoSegment(int magic, signed char version, signed char hashAlgorithm,
                                         signed char log2BlockSize, std::vector<int8_t> reserved)
{
    this->magic = magic;
    this->version = version;
    this->hashAlgorithm = hashAlgorithm;
    this->log2BlockSize = log2BlockSize;
    this->reserved = reserved;
}

FsVerityInfoSegment:: ~FsVerityInfoSegment()
{
}

int FsVerityInfoSegment::Size()
{
    return FS_VERITY_INFO_SEGMENT_SIZE;
}

std::vector<int8_t> FsVerityInfoSegment::ToByteArray()
{
    ByteBuffer bf(FS_VERITY_INFO_SEGMENT_SIZE);
    bf.PutInt32(this->magic);
    bf.PutByte(version);
    bf.PutByte(hashAlgorithm);
    bf.PutByte(log2BlockSize);
    bf.PutData(reserved.data(), reserved.size());
    std::vector<int8_t> ret(bf.GetBufferPtr(), bf.GetBufferPtr() + bf.GetPosition());
    return ret;
}

FsVerityInfoSegment FsVerityInfoSegment::FromByteArray(std::vector<int8_t> bytes)
{
    if (bytes.size() != FS_VERITY_INFO_SEGMENT_SIZE) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid size of FsVerityInfoSegment");
        return FsVerityInfoSegment();
    }

    // 构建ByteBuffer
    ByteBuffer bf(bytes.size());

    bf.PutData((const char*)bytes.data(), bytes.size());
    bf.SetPosition(0);
    int inMagic;
    bf.GetInt32(inMagic);
    if (inMagic != MAGIC) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid magic number of FsVerityInfoSegment");
        return FsVerityInfoSegment();
    }

    signed char inVersion;
    bf.GetInt8(inVersion);
    if (inVersion != FsVerityDescriptor::VERSION) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid version of FsVerityInfoSegment");
        return FsVerityInfoSegment();
    }

    signed char inHashAlgorithm;
    bf.GetInt8(inHashAlgorithm);
    if (inHashAlgorithm != FsVerityGenerator::GetFsVerityHashAlgorithm()) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid hashAlgorithm of FsVerityInfoSegment");
        return FsVerityInfoSegment();
    }

    signed char inLog2BlockSize;
    bf.GetInt8(inLog2BlockSize);
    if (inLog2BlockSize != FsVerityGenerator::GetLog2BlockSize()) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid log2BlockSize of FsVerityInfoSegment");
        return FsVerityInfoSegment();
    }

    std::vector<signed char> inReservedBytes(RESERVED_BYTE_ARRAY_LENGTH);
    char reverseArr[RESERVED_BYTE_ARRAY_LENGTH];
    bf.GetData(reverseArr, RESERVED_BYTE_ARRAY_LENGTH);
    std::vector<int8_t> reverseData(reverseArr, reverseArr + RESERVED_BYTE_ARRAY_LENGTH);

    return FsVerityInfoSegment(inMagic, inVersion, inHashAlgorithm, inLog2BlockSize, reverseData);
}

}
}