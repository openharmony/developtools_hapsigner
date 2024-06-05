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
#include "zip_entry_header.h"

#include "signature_tools_log.h"
#include "unsigned_decimal_util.h"

using namespace OHOS::SignatureTools;

ZipEntryHeader* ZipEntryHeader::GetZipEntryHeader(std::vector<char> &bytes)
{
    ZipEntryHeader* entryHeader = new ZipEntryHeader();
    ByteBuffer bf((const char *)bytes.data(), bytes.size());

    int32_t entryHeaderInt32Value;
    bf.GetInt32(entryHeaderInt32Value);
    if (entryHeaderInt32Value != ZipEntryHeader::SIGNATURE) {
        delete entryHeader;
        SIGNATURE_TOOLS_LOGE("find zip entry head failed");
        return nullptr;
    }

    int16_t entryHeaderInt16Value;
    bf.GetInt16(entryHeaderInt16Value);
    entryHeader->SetVersion(entryHeaderInt16Value);

    bf.GetInt16(entryHeaderInt16Value);
    entryHeader->SetFlag(entryHeaderInt16Value);

    bf.GetInt16(entryHeaderInt16Value);
    entryHeader->SetMethod(entryHeaderInt16Value);

    bf.GetInt16(entryHeaderInt16Value);
    entryHeader->SetLastTime(entryHeaderInt16Value);

    bf.GetInt16(entryHeaderInt16Value);
    entryHeader->SetLastDate(entryHeaderInt16Value);

    bf.GetInt32(entryHeaderInt32Value);
    entryHeader->SetCrc32(entryHeaderInt32Value);

    entryHeader->SetCompressedSize(UnsignedDecimalUtil::GetUnsignedInt(bf));
    entryHeader->SetUnCompressedSize(UnsignedDecimalUtil::GetUnsignedInt(bf));
    entryHeader->SetFileNameLength(UnsignedDecimalUtil::GetUnsignedShort(bf));
    entryHeader->SetExtraLength(UnsignedDecimalUtil::GetUnsignedShort(bf));
    entryHeader->SetLength(HEADER_LENGTH + entryHeader->GetFileNameLength() + entryHeader->GetExtraLength());

    return entryHeader;
}

void ZipEntryHeader::ReadFileName(std::vector<char>& bytes)
{
    this->fileName = std::string(bytes.begin(), bytes.end());
}

void ZipEntryHeader::ReadExtra(std::vector<char>& bytes)
{
    ByteBuffer bf(bytes.data(), bytes.size());
    if (extraLength > 0) {
        char* pExtra = new char[extraLength];
        bf.GetData(pExtra, extraLength);

        for (int i = 0; i < extraLength; ++i) {
            this->extraData.push_back(pExtra[i]);
        }

        delete[] pExtra;
    }
}

std::vector<char> ZipEntryHeader::ToBytes()
{
    ByteBuffer bf(length);

    bf.PutInt32(SIGNATURE);
    bf.PutInt16(version);
    bf.PutInt16(flag);
    bf.PutInt16(method);
    bf.PutInt16(lastTime);
    bf.PutInt16(lastDate);
    bf.PutInt32(crc32);
    UnsignedDecimalUtil::SetUnsignedInt(bf, compressedSize);
    UnsignedDecimalUtil::SetUnsignedInt(bf, unCompressedSize);
    UnsignedDecimalUtil::SetUnsignedShort(bf, fileNameLength);
    UnsignedDecimalUtil::SetUnsignedShort(bf, extraLength);
    if (fileNameLength > 0) {
        bf.PutData((const char*)fileName.c_str(), fileName.size());
    }
    if (extraLength > 0) {
        bf.PutData(extraData.data(), extraData.size());
    }

    bf.Flip();
    char* retBuf = new char[length];
    bf.GetData(retBuf, length);
    std::vector<char> retVec(retBuf, retBuf + length);
    delete[] retBuf;
    return retVec;
}

int ZipEntryHeader::GetHeaderLength()
{
    return HEADER_LENGTH;
}

int ZipEntryHeader::GetSIGNATURE()
{
    return SIGNATURE;
}

short ZipEntryHeader::GetVersion()
{
    return version;
}

void ZipEntryHeader::SetVersion(short version)
{
    this->version = version;
}

short ZipEntryHeader::GetFlag()
{
    return flag;
}

void ZipEntryHeader::SetFlag(short flag)
{
    this->flag = flag;
}

short ZipEntryHeader::GetMethod()
{
    return method;
}

void ZipEntryHeader::SetMethod(short method)
{
    this->method = method;
}

short ZipEntryHeader::GetLastTime()
{
    return lastTime;
}

void ZipEntryHeader::SetLastTime(short lastTime)
{
    this->lastTime = lastTime;
}

short ZipEntryHeader::GetLastDate()
{
    return lastDate;
}

void ZipEntryHeader::SetLastDate(short lastDate)
{
    this->lastDate = lastDate;
}

int ZipEntryHeader::GetCrc32()
{
    return crc32;
}

void ZipEntryHeader::SetCrc32(int crc32)
{
    this->crc32 = crc32;
}

long long ZipEntryHeader::GetCompressedSize()
{
    return compressedSize;
}

void ZipEntryHeader::SetCompressedSize(long long compressedSize)
{
    this->compressedSize = compressedSize;
}

long long ZipEntryHeader::GetUnCompressedSize()
{
    return unCompressedSize;
}

void ZipEntryHeader::SetUnCompressedSize(long long unCompressedSize)
{
    this->unCompressedSize = unCompressedSize;
}

int ZipEntryHeader::GetFileNameLength()
{
    return fileNameLength;
}

void ZipEntryHeader::SetFileNameLength(int fileNameLength)
{
    this->fileNameLength = fileNameLength;
}

int ZipEntryHeader::GetExtraLength()
{
    return extraLength;
}

void ZipEntryHeader::SetExtraLength(int extraLength)
{
    this->extraLength = extraLength;
}

std::string ZipEntryHeader::GetFileName()
{
    return fileName;
}

void ZipEntryHeader::SetFileName(const std::string& fileName)
{
    this->fileName = fileName;
}

std::vector<char> ZipEntryHeader::GetExtraData()
{
    return extraData;
}

void ZipEntryHeader::SetExtraData(std::vector<char>& extraData)
{
    this->extraData = extraData;
}

int ZipEntryHeader::GetLength()
{
    return length;
}

void ZipEntryHeader::SetLength(int length)
{
    this->length = length;
}