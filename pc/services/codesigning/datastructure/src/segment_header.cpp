/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "segment_header.h"

using namespace OHOS::SignatureTools;

SegmentHeader::SegmentHeader()
{
}

SegmentHeader::SegmentHeader(int32_t type, int32_t segmentSize) :type(type), segmentOffset(0), segmentSize(segmentSize)
{
}

SegmentHeader::SegmentHeader(int32_t type, int32_t segmentOffset,
    int32_t segmentSize)
{
    this->type = type;
    this->segmentOffset = segmentOffset;
    this->segmentSize = segmentSize;
}

int32_t SegmentHeader::getType()
{
    return type;
}

void SegmentHeader::setSegmentOffset(int32_t offset)
{
    this->segmentOffset = offset;
}

int32_t SegmentHeader::getSegmentOffset()
{
    return segmentOffset;
}

int32_t SegmentHeader::getSegmentSize()
{
    return segmentSize;
}

std::vector<int8_t> SegmentHeader::toByteArray()
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(SEGMENT_HEADER_LENGTH));
    bf->PutInt32(type);
    bf->PutInt32(segmentOffset);
    bf->PutInt32(segmentSize);
    bf->Flip();
    std::vector<int8_t> ret(bf->GetBufferPtr(), bf->GetBufferPtr() + bf.get()->GetLimit());
    return ret;
}

std::unique_ptr<SegmentHeader> SegmentHeader::fromByteArray(std::vector<int8_t> bytes)
{
    if (bytes.size() != SEGMENT_HEADER_LENGTH) {
        SIGNATURE_TOOLS_LOGE("Invalid size of SegmentHeader");
        return std::unique_ptr<SegmentHeader>();
    }
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(SEGMENT_HEADER_LENGTH));
    bf->PutData((char*)bytes.data(), bytes.size());
    bf->Flip();
    int32_t inType = 0;
    bf->GetInt32(inType);
    if ((inType != CSB_FSVERITY_INFO_SEG) && (inType != CSB_HAP_META_SEG)
        && (inType != CSB_NATIVE_LIB_INFO_SEG)) {
        SIGNATURE_TOOLS_LOGE("Invalid type of SegmentHeader");
        return std::unique_ptr<SegmentHeader>();
    }
    int32_t inSegmentOffset = 0;
    bf->GetInt32(inSegmentOffset);
    // segment offset is always larger than the size of CodeSignBlockHeader
    int32_t inSegmentSize = 0;
    bf->GetInt32(inSegmentSize);
    if (inSegmentSize < 0) {
        SIGNATURE_TOOLS_LOGE("Invalid segmentSize of SegmentHeader");
        return std::unique_ptr<SegmentHeader>();
    }
    return std::make_unique<SegmentHeader>(inType, inSegmentOffset, inSegmentSize);
}