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
#include "endof_central_directory.h"
#include "unsigned_decimal_util.h"
#include "signature_tools_log.h"

using namespace OHOS::SignatureTools;

std::optional<EndOfCentralDirectory *> EndOfCentralDirectory::GetEOCDByBytes(std::vector<char> &bytes)
{
    return GetEOCDByBytes(bytes, 0);
}

std::optional<EndOfCentralDirectory *> EndOfCentralDirectory::GetEOCDByBytes(std::vector<char> &bytes, int offset)
{
    EndOfCentralDirectory *eocd = new EndOfCentralDirectory();
    int remainingDataLen = bytes.size() - offset;
    if (remainingDataLen < EOCD_LENGTH) {
        delete eocd;
        SIGNATURE_TOOLS_LOGE("remainingDataLen is less than EOCD_LENGTH, remainingDataLen: %{public}d, \
            EOCD_LENGTH: %{public}d", remainingDataLen, EOCD_LENGTH);
        return std::nullopt;
    }

    ByteBuffer bf(bytes.data(), bytes.size());

    int signValue;
    bf.GetInt32(signValue);
    if (signValue != SIGNATURE) {
        delete eocd;
        SIGNATURE_TOOLS_LOGE("signValue is not equal to SIGNATURE, signValue: %{public}d, SIGNATURE: %{public}d",
            signValue, SIGNATURE);
        return std::nullopt;
    }
    eocd->SetDiskNum(UnsignedDecimalUtil::GetUnsignedShort(bf));
    eocd->SetcDStartDiskNum(UnsignedDecimalUtil::GetUnsignedShort(bf));
    eocd->SetThisDiskCDNum(UnsignedDecimalUtil::GetUnsignedShort(bf));
    eocd->SetcDTotal(UnsignedDecimalUtil::GetUnsignedShort(bf));
    eocd->SetcDSize(UnsignedDecimalUtil::GetUnsignedInt(bf));
    eocd->SetOffset(UnsignedDecimalUtil::GetUnsignedInt(bf));
    eocd->SetCommentLength(UnsignedDecimalUtil::GetUnsignedShort(bf));
    int commentLength = eocd->GetCommentLength();
    if (bf.Remaining() != commentLength) {
        delete eocd;
        SIGNATURE_TOOLS_LOGE("bf.Remaining() is not equal to commentLength, bf.Remaining(): %{public}d, "\
                             "commentLength: %{public}d", bf.Remaining(), commentLength);
        return std::nullopt;
    }
    if (commentLength > 0) {
        char *readComment = new char[commentLength];
        bf.GetData(readComment, commentLength);
        std::vector<char> readCommentVec(readComment, readComment + commentLength);

        delete[] readComment;
        eocd->SetComment(readCommentVec);
    }
    eocd->SetLength(EOCD_LENGTH + commentLength);
    if (bf.Remaining() != 0) {
        delete eocd;
        SIGNATURE_TOOLS_LOGE("bf.Remaining() is not zero, bf.Remaining(): %{public}d", bf.Remaining());
        return std::nullopt;
    }
    return std::make_optional(eocd);
}

std::vector<char> EndOfCentralDirectory::ToBytes()
{
    ByteBuffer bf(length);

    bf.PutInt32(SIGNATURE);
    UnsignedDecimalUtil::SetUnsignedShort(bf, diskNum);
    UnsignedDecimalUtil::SetUnsignedShort(bf, cDStartDiskNum);
    UnsignedDecimalUtil::SetUnsignedShort(bf, thisDiskCDNum);
    UnsignedDecimalUtil::SetUnsignedShort(bf, cDTotal);
    UnsignedDecimalUtil::SetUnsignedInt(bf, cDSize);
    UnsignedDecimalUtil::SetUnsignedInt(bf, offset);
    UnsignedDecimalUtil::SetUnsignedShort(bf, commentLength);
    if (commentLength > 0) {
        bf.PutData(comment.data(), comment.size());
    }

    std::vector<char> res(bf.GetBufferPtr(), bf.GetBufferPtr() + bf.GetCapacity());
    return res;
}

int EndOfCentralDirectory::GetEocdLength()
{
    return EOCD_LENGTH;
}

int EndOfCentralDirectory::GetSIGNATURE()
{
    return SIGNATURE;
}

int EndOfCentralDirectory::GetDiskNum()
{
    return diskNum;
}

void EndOfCentralDirectory::SetDiskNum(int diskNum)
{
    this->diskNum = diskNum;
}

int EndOfCentralDirectory::GetcDStartDiskNum()
{
    return cDStartDiskNum;
}

void EndOfCentralDirectory::SetcDStartDiskNum(int cDStartDiskNum)
{
    this->cDStartDiskNum = cDStartDiskNum;
}

int EndOfCentralDirectory::GetThisDiskCDNum()
{
    return thisDiskCDNum;
}

void EndOfCentralDirectory::SetThisDiskCDNum(int thisDiskCDNum)
{
    this->thisDiskCDNum = thisDiskCDNum;
}

int EndOfCentralDirectory::GetcDTotal()
{
    return cDTotal;
}

void EndOfCentralDirectory::SetcDTotal(int cDTotal)
{
    this->cDTotal = cDTotal;
}

uint64_t EndOfCentralDirectory::GetcDSize()
{
    return cDSize;
}

void EndOfCentralDirectory::SetcDSize(uint64_t cDSize)
{
    this->cDSize = cDSize;
}

uint64_t EndOfCentralDirectory::GetOffset()
{
    return offset;
}

void EndOfCentralDirectory::SetOffset(uint64_t offset)
{
    this->offset = offset;
}

int EndOfCentralDirectory::GetCommentLength()
{
    return commentLength;
}

void EndOfCentralDirectory::SetCommentLength(int commentLength)
{
    this->commentLength = commentLength;
}

std::vector<char> EndOfCentralDirectory::GetComment()
{
    return comment;
}

void EndOfCentralDirectory::SetComment(std::vector<char> &comment)
{
    this->comment = comment;
}

int EndOfCentralDirectory::GetLength()
{
    return length;
}

void EndOfCentralDirectory::SetLength(int length)
{
    this->length = length;
}