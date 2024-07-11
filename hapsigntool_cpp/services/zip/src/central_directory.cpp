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

#include "central_directory.h"
#include "signature_tools_log.h"
#include "unsigned_decimal_util.h"

namespace OHOS {
namespace SignatureTools {
bool CentralDirectory::GetCentralDirectory(ByteBuffer& bf, CentralDirectory* cd)
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
        std::string readFileName(fileNameLength, 0);
        bf.GetData(&readFileName[0], fileNameLength);
        cd->SetFileName(readFileName);
    }
    int extraLength = cd->GetExtraLength();
    if (extraLength > 0) {
        std::string extra(extraLength, 0);
        bf.GetData(&extra[0], extraLength);
        cd->SetExtraData(extra);
    }
    int commentLength = cd->GetCommentLength();
    if (commentLength > 0) {
        std::string readComment(commentLength, 0);
        bf.GetData(&readComment[0], commentLength);
        cd->SetComment(readComment);
    }
    cd->SetLength(CD_LENGTH + fileNameLength + extraLength + commentLength);

    return true;
}

void CentralDirectory::SetCentralDirectoryValues(ByteBuffer& bf, CentralDirectory* cd)
{
    int16_t centralDirectoryInt16Value;
    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetVersion(centralDirectoryInt16Value);

    bf.GetInt16(centralDirectoryInt16Value);
    cd->SetVersionExtra(centralDirectoryInt16Value);

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

std::string CentralDirectory::ToBytes()
{
    ByteBuffer bf(m_length);

    bf.PutInt32(SIGNATURE);
    UnsignedDecimalUtil::SetUnsignedShort(bf, m_version);
    UnsignedDecimalUtil::SetUnsignedShort(bf, m_versionExtra);
    UnsignedDecimalUtil::SetUnsignedShort(bf, m_flag);
    UnsignedDecimalUtil::SetUnsignedShort(bf, m_method);
    UnsignedDecimalUtil::SetUnsignedShort(bf, m_lastTime);
    UnsignedDecimalUtil::SetUnsignedShort(bf, m_lastDate);
    UnsignedDecimalUtil::SetUnsignedInt(bf, m_crc32);
    UnsignedDecimalUtil::SetUnsignedInt(bf, m_compressedSize);
    UnsignedDecimalUtil::SetUnsignedInt(bf, m_unCompressedSize);
    UnsignedDecimalUtil::SetUnsignedShort(bf, m_fileNameLength);
    UnsignedDecimalUtil::SetUnsignedShort(bf, m_extraLength);
    UnsignedDecimalUtil::SetUnsignedShort(bf, m_commentLength);
    UnsignedDecimalUtil::SetUnsignedShort(bf, m_diskNumStart);
    UnsignedDecimalUtil::SetUnsignedShort(bf, m_internalFile);
    UnsignedDecimalUtil::SetUnsignedInt(bf, m_externalFile);
    UnsignedDecimalUtil::SetUnsignedInt(bf, m_offset);
    if (m_fileNameLength > 0) {
        bf.PutData(m_fileName.c_str(), m_fileName.size());
    }
    if (m_extraLength > 0) {
        bf.PutData(m_extraData.c_str(), m_extraData.size());
    }
    if (m_commentLength > 0) {
        bf.PutData(m_extraData.c_str(), m_extraData.size());
    }

    return bf.ToString();
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
    return m_version;
}

void CentralDirectory::SetVersion(short version)
{
    m_version = version;
}

short CentralDirectory::GetVersionExtra()
{
    return m_versionExtra;
}

void CentralDirectory::SetVersionExtra(short versionExtra)
{
    m_versionExtra = versionExtra;
}

short CentralDirectory::GetFlag()
{
    return m_flag;
}

void CentralDirectory::SetFlag(short flag)
{
    m_flag = flag;
}

short CentralDirectory::GetMethod()
{
    return m_method;
}

void CentralDirectory::SetMethod(short method)
{
    m_method = method;
}

short CentralDirectory::GetLastTime()
{
    return m_lastTime;
}

void CentralDirectory::SetLastTime(short lastTime)
{
    m_lastTime = lastTime;
}

short CentralDirectory::GetLastDate()
{
    return m_lastDate;
}

void CentralDirectory::SetLastDate(short lastDate)
{
    m_lastDate = lastDate;
}

int CentralDirectory::GetCrc32()
{
    return m_crc32;
}

void CentralDirectory::SetCrc32(int crc32)
{
    m_crc32 = crc32;
}

int64_t CentralDirectory::GetCompressedSize()
{
    return m_compressedSize;
}

void CentralDirectory::SetCompressedSize(int64_t compressedSize)
{
    m_compressedSize = compressedSize;
}

int64_t CentralDirectory::GetUnCompressedSize()
{
    return m_unCompressedSize;
}

void CentralDirectory::SetUnCompressedSize(int64_t unCompressedSize)
{
    m_unCompressedSize = unCompressedSize;
}

int CentralDirectory::GetFileNameLength()
{
    return m_fileNameLength;
}

void CentralDirectory::SetFileNameLength(int fileNameLength)
{
    m_fileNameLength = fileNameLength;
}

int CentralDirectory::GetExtraLength()
{
    return m_extraLength;
}

void CentralDirectory::SetExtraLength(int extraLength)
{
    m_extraLength = extraLength;
}

int CentralDirectory::GetCommentLength()
{
    return m_commentLength;
}

void CentralDirectory::SetCommentLength(int commentLength)
{
    m_commentLength = commentLength;
}

int CentralDirectory::GetDiskNumStart()
{
    return m_diskNumStart;
}

void CentralDirectory::SetDiskNumStart(int diskNumStart)
{
    m_diskNumStart = diskNumStart;
}

short CentralDirectory::GetInternalFile()
{
    return m_internalFile;
}

void CentralDirectory::SetInternalFile(short internalFile)
{
    m_internalFile = internalFile;
}

int CentralDirectory::GetExternalFile()
{
    return m_externalFile;
}

void CentralDirectory::SetExternalFile(int externalFile)
{
    m_externalFile = externalFile;
}

int64_t CentralDirectory::GetOffset()
{
    return m_offset;
}

void CentralDirectory::SetOffset(int64_t offset)
{
    m_offset = offset;
}

std::string CentralDirectory::GetFileName()
{
    return m_fileName;
}

void CentralDirectory::SetFileName(const std::string& fileName)
{
    m_fileName = fileName;
}

std::string CentralDirectory::GetExtraData() const
{
    return m_extraData;
}

void CentralDirectory::SetExtraData(const std::string& extraData)
{
    m_extraData = extraData;
}

std::string CentralDirectory::GetComment()
{
    return m_comment;
}

void CentralDirectory::SetComment(const std::string& comment)
{
    m_comment = comment;
}

int CentralDirectory::GetLength()
{
    return m_length;
}

void CentralDirectory::SetLength(int length)
{
    m_length = length;
}
} // namespace SignatureTools
} // namespace OHOS