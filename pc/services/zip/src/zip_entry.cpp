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
#include "zip_entry.h"
#include <stdexcept>
#include "signature_tools_log.h"
#include "unsigned_decimal_util.h"

using namespace OHOS::SignatureTools;

int ZipEntry::Alignment(int alignNum)
{
    // if cd extra len bigger than entry extra len, make cd and entry extra
    // length equals
    if(alignNum==0)
        return -1;
    int padding = CalZeroPaddingLengthForEntryExtra();
    int remainder = (zipEntryData->GetZipEntryHeader()->GetLength() + fileEntryIncentralDirectory->GetOffset()) %
                     alignNum;
    if (remainder == 0) {
        return padding;
    }
    int add = alignNum - remainder;
    int newExtraLength = zipEntryData->GetZipEntryHeader()->GetExtraLength() + add;
    if (newExtraLength > UnsignedDecimalUtil::MAX_UNSIGNED_SHORT_VALUE) {
        SIGNATURE_TOOLS_LOGE("newExtraLength is greater than 65535, cannot align");
        return -1;
    }
    SetEntryHeaderNewExtraLength(newExtraLength);
    SetCenterDirectoryNewExtraLength(newExtraLength);

    return add;
}

int ZipEntry::CalZeroPaddingLengthForEntryExtra()
{
    int entryExtraLen = zipEntryData->GetZipEntryHeader()->GetExtraLength();
    int cdExtraLen = fileEntryIncentralDirectory->GetExtraLength();
    if (cdExtraLen > entryExtraLen) {
        SetEntryHeaderNewExtraLength(cdExtraLen);
        return cdExtraLen - entryExtraLen;
    }
    if (cdExtraLen < entryExtraLen) {
        SetCenterDirectoryNewExtraLength(entryExtraLen);
        return entryExtraLen - cdExtraLen;
    }
    return 0;
}

void ZipEntry::SetCenterDirectoryNewExtraLength(int newLength)
{
    std::vector<char> oldExtraData = fileEntryIncentralDirectory->GetExtraData();
    std::vector<char> newCDExtra = GetAlignmentNewExtra(newLength, oldExtraData);
    fileEntryIncentralDirectory->SetExtraData(newCDExtra);
    fileEntryIncentralDirectory->SetExtraLength(newLength);
    fileEntryIncentralDirectory->SetLength(
        CentralDirectory::CD_LENGTH +
        fileEntryIncentralDirectory->GetFileNameLength() +
        fileEntryIncentralDirectory->GetExtraLength() +
        fileEntryIncentralDirectory->GetCommentLength());
}

void ZipEntry::SetEntryHeaderNewExtraLength(int newLength)
{
    ZipEntryHeader* zipEntryHeader = zipEntryData->GetZipEntryHeader();
    std::vector<char> oldExtraData = zipEntryHeader->GetExtraData();
    std::vector<char> newExtra = GetAlignmentNewExtra(newLength, oldExtraData);
    zipEntryHeader->SetExtraData(newExtra);
    zipEntryHeader->SetExtraLength(newLength);
    zipEntryHeader->SetLength(ZipEntryHeader::HEADER_LENGTH + zipEntryHeader->GetExtraLength() +
                              zipEntryHeader->GetFileNameLength());
    zipEntryData->SetLength(zipEntryHeader->GetLength() +
                            zipEntryData->GetFileSize() +
                            (zipEntryData->GetDataDescriptor() == nullptr ? 0 : DataDescriptor::DES_LENGTH));
}

std::vector<char> ZipEntry::GetAlignmentNewExtra(int newLength, std::vector<char>& old)
{
    if (old.empty()) {
        return std::vector<char>(newLength);
    }
    if (newLength < (int)old.size()) {
        SIGNATURE_TOOLS_LOGE("cannot align");
        return std::vector<char>(newLength);
    }
    std::vector<char> tmpVec(old);
    tmpVec.resize(newLength, 0);
    return tmpVec;
}

ZipEntryData* ZipEntry::GetZipEntryData()
{
    return zipEntryData;
}

void ZipEntry::SetZipEntryData(ZipEntryData* zipEntryData)
{
    this->zipEntryData = zipEntryData;
}

CentralDirectory* ZipEntry::GetCentralDirectory()
{
    return fileEntryIncentralDirectory;
}

void ZipEntry::SetCentralDirectory(CentralDirectory* centralDirectory)
{
    this->fileEntryIncentralDirectory = centralDirectory;
}