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
#include "central_directory.h"
#include "unsigned_decimal_util.h"
#include "signature_tools_log.h"

using namespace OHOS::SignatureTools;

bool CentralDirectory::GetCentralDirectory(ByteBuffer &bf, CentralDirectory *cd)
{
    int signatureValue;
    bf.GetInt32(signatureValue);
    if (signatureValue != SIGNATURE) {
        SIGNATURE_TOOLS_LOGE("find zip central directory failed");
        return false;
    }

    SetCentralDirectoryValues(bf, cd);

    int fileNameLength = cd->GetFileNameLength();
    if (fileNameLength > 0) {
        char *readFileName = new char[fileNameLength];
        bf.GetData(readFileName, fileNameLength);
        std::string fileNameStr(readFileName, fileNameLength);
        cd->SetFileName(fileNameStr);
        delete[] readFileName;
    }
    int extraLength = cd->GetExtraLength();
    if (extraLength > 0) {
        char *extra = new char[extraLength];
        bf.GetData(extra, extraLength);
        std::vector<char> extraData(extra, extra + extraLength);
        cd->SetExtraData(extraData);
        delete[] extra;
    }
    int commentLength = cd->GetCommentLength();
    if (commentLength > 0) {
        char *readComment = new char[commentLength];
        bf.GetData(readComment, commentLength);
        std::vector<char> comment(readComment, readComment + commentLength);
        cd->SetComment(comment);
        delete[] readComment;
    }
    cd->SetLength(CD_LENGTH + fileNameLength + extraLength + commentLength);

    return true;
}

void CentralDirectory::SetCentralDirectoryValues(ByteBuffer &bf, CentralDirectory *cd)
{
    int16_t centralDirectoryInt16Value;
    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetVersionExtra(centralDirectoryInt16Value);

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetVersion(centralDirectoryInt16Value);

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetFlag(centralDirectoryInt16Value);

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetMethod(centralDirectoryInt16Value);

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetLastTime(centralDirectoryInt16Value);

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetLastDate(centralDirectoryInt16Value);

    int32_t centralDirectoryInt32Value;
    bf.GetInt32(centralDirectoryInt32Value);
    cd->SetCrc32(centralDirectoryInt32Value);

    cd->SetCompressedSize(UnsignedDecimalUtil::GetUnsignedInt(bf));
    cd->SetUnCompressedSize(UnsignedDecimalUtil::GetUnsignedInt(bf));
    cd->SetFileNameLength(UnsignedDecimalUtil::GetUnsignedShort(bf));
    cd->SetExtraLength(UnsignedDecimalUtil::GetUnsignedShort(bf));
    cd->SetCommentLength(UnsignedDecimalUtil::GetUnsignedShort(bf));
    cd->SetDiskNumStart(UnsignedDecimalUtil::GetUnsignedShort(bf));

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetInternalFile(centralDirectoryInt16Value);

    bf.GetInt32(centralDirectoryInt32Value);
    cd->SetExternalFile(centralDirectoryInt32Value);

    cd->SetOffset(UnsignedDecimalUtil::GetUnsignedInt(bf));
}

std::vector<char> CentralDirectory::ToBytes()
{
    ByteBuffer bf(length);

    bf.PutInt32(SIGNATURE);
    UnsignedDecimalUtil::SetUnsignedShort(bf, version);
    UnsignedDecimalUtil::SetUnsignedShort(bf, versionExtra);
    UnsignedDecimalUtil::SetUnsignedShort(bf, flag);
    UnsignedDecimalUtil::SetUnsignedShort(bf, method);
    UnsignedDecimalUtil::SetUnsignedShort(bf, lastTime);
    UnsignedDecimalUtil::SetUnsignedShort(bf, lastDate);
    UnsignedDecimalUtil::SetUnsignedInt(bf, crc32);
    UnsignedDecimalUtil::SetUnsignedInt(bf, compressedSize);
    UnsignedDecimalUtil::SetUnsignedInt(bf, unCompressedSize);
    UnsignedDecimalUtil::SetUnsignedShort(bf, fileNameLength);
    UnsignedDecimalUtil::SetUnsignedShort(bf, extraLength);
    UnsignedDecimalUtil::SetUnsignedShort(bf, commentLength);
    UnsignedDecimalUtil::SetUnsignedShort(bf, diskNumStart);
    UnsignedDecimalUtil::SetUnsignedShort(bf, internalFile);
    UnsignedDecimalUtil::SetUnsignedInt(bf, externalFile);
    UnsignedDecimalUtil::SetUnsignedInt(bf, offset);
    if (fileNameLength > 0) {
        bf.PutData(fileName.c_str(), fileName.size());
    }
    if (extraLength > 0) {
        bf.PutData(extraData.data(), extraData.size());
    }
    if (commentLength > 0) {
        bf.PutData(extraData.data(), extraData.size());
    }

    std::vector<char> retVec(bf.GetBufferPtr(), bf.GetBufferPtr() + bf.GetCapacity());
    return retVec;
}

int CentralDirectory::GetCdLength()
{
    return CD_LENGTH;
}

int CentralDirectory::GetSIGNATURE()
{
    return SIGNATURE;
}

short CentralDirectory::GetVersion()
{
    return version;
}

void CentralDirectory::SetVersion(short version)
{
    this->version = version;
}

short CentralDirectory::GetVersionExtra()
{
    return versionExtra;
}

void CentralDirectory::SetVersionExtra(short versionExtra)
{
    this->versionExtra = versionExtra;
}

short CentralDirectory::GetFlag()
{
    return flag;
}

void CentralDirectory::SetFlag(short flag)
{
    this->flag = flag;
}

short CentralDirectory::GetMethod()
{
    return method;
}

void CentralDirectory::SetMethod(short method)
{
    this->method = method;
}

short CentralDirectory::GetLastTime()
{
    return lastTime;
}

void CentralDirectory::SetLastTime(short lastTime)
{
    this->lastTime = lastTime;
}

short CentralDirectory::GetLastDate()
{
    return lastDate;
}

void CentralDirectory::SetLastDate(short lastDate)
{
    this->lastDate = lastDate;
}

int CentralDirectory::GetCrc32()
{
    return crc32;
}

void CentralDirectory::SetCrc32(int crc32)
{
    this->crc32 = crc32;
}

long long CentralDirectory::GetCompressedSize()
{
    return compressedSize;
}

void CentralDirectory::SetCompressedSize(long long compressedSize)
{
    this->compressedSize = compressedSize;
}

long long CentralDirectory::GetUnCompressedSize()
{
    return unCompressedSize;
}

void CentralDirectory::SetUnCompressedSize(long long unCompressedSize)
{
    this->unCompressedSize = unCompressedSize;
}

int CentralDirectory::GetFileNameLength()
{
    return fileNameLength;
}

void CentralDirectory::SetFileNameLength(int fileNameLength)
{
    this->fileNameLength = fileNameLength;
}

int CentralDirectory::GetExtraLength()
{
    return extraLength;
}

void CentralDirectory::SetExtraLength(int extraLength)
{
    this->extraLength = extraLength;
}

int CentralDirectory::GetCommentLength()
{
    return commentLength;
}

void CentralDirectory::SetCommentLength(int commentLength)
{
    this->commentLength = commentLength;
}

int CentralDirectory::GetDiskNumStart()
{
    return diskNumStart;
}

void CentralDirectory::SetDiskNumStart(int diskNumStart)
{
    this->diskNumStart = diskNumStart;
}

short CentralDirectory::GetInternalFile()
{
    return internalFile;
}

void CentralDirectory::SetInternalFile(short internalFile)
{
    this->internalFile = internalFile;
}

int CentralDirectory::GetExternalFile()
{
    return externalFile;
}

void CentralDirectory::SetExternalFile(int externalFile)
{
    this->externalFile = externalFile;
}

long long CentralDirectory::GetOffset()
{
    return offset;
}

void CentralDirectory::SetOffset(long long offset)
{
    this->offset = offset;
}

std::string CentralDirectory::GetFileName()
{
    return fileName;
}

void CentralDirectory::SetFileName(const std::string &fileName)
{
    this->fileName = fileName;
}

std::vector<char> CentralDirectory::GetExtraData()
{
    return extraData;
}

void CentralDirectory::SetExtraData(std::vector<char> &extraData)
{
    this->extraData = extraData;
}

std::vector<char> CentralDirectory::GetComment()
{
    return comment;
}

void CentralDirectory::SetComment(std::vector<char> &comment)
{
    this->comment = comment;
}

int CentralDirectory::GetLength()
{
    return length;
}

void CentralDirectory::SetLength(int length)
{
    this->length = length;
}