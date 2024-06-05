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
#include "zip_signer.h"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include "file_utils.h"
#include "zip_entry.h"

using namespace OHOS::SignatureTools;

bool Zip::Init(std::ifstream& inputFile)
{
    if (!inputFile.good()) {
        return false;
    }

    // 1. get eocd data
    endOfCentralDirectory = GetZipEndOfCentralDirectory(inputFile);
    if (!endOfCentralDirectory) {
        SIGNATURE_TOOLS_LOGE("get eocd data failed.");
        return false;
    }

    cDOffset = endOfCentralDirectory->GetOffset();

    // 2. use eocd's cd offset, get cd data
    if (!GetZipCentralDirectory(inputFile)) {
        SIGNATURE_TOOLS_LOGE("get zip central directory failed.");
        return false;
    }

    // 3. use cd's entry offset and file size, get entry data
    if (!GetZipEntries(inputFile)) {
        SIGNATURE_TOOLS_LOGE("get zip entries failed.");
        return false;
    }

    ZipEntry* endEntry = zipEntries[zipEntries.size() - 1];
    CentralDirectory* endCD = endEntry->GetCentralDirectory();
    ZipEntryData* endEntryData = endEntry->GetZipEntryData();
    signingOffset = endCD->GetOffset() + endEntryData->GetLength();
    // 4. file all data - eocd - cd - entry = sign block
    signingBlock = GetSigningBlock(inputFile);

    return true;
}

EndOfCentralDirectory* Zip::GetZipEndOfCentralDirectory(std::ifstream& input)
{
    // move file pointer to the end
    input.seekg(0, std::ios::end);
    uint64_t fileSize = input.tellg();
    // move file pointer to the begin
    input.seekg(0, std::ios::beg);

    if (fileSize < EndOfCentralDirectory::EOCD_LENGTH) {
        SIGNATURE_TOOLS_LOGE("find zip eocd failed");
        return nullptr;
    }

    // try to read EOCD without comment
    int eocdLength = EndOfCentralDirectory::EOCD_LENGTH;
    eOCDOffset = fileSize - eocdLength;

    std::string retStr;
    int ret = FileUtils::ReadFileByOffsetAndLength(input, eOCDOffset, eocdLength, retStr);
    if (0 != ret) {
        SIGNATURE_TOOLS_LOGE("ReadFileByOffsetAndLength error");
        return nullptr;
    }
    std::vector<char> bytes(retStr.begin(), retStr.end());

    std::optional<EndOfCentralDirectory*> eocdByBytes = EndOfCentralDirectory::GetEOCDByBytes(bytes);
    if (eocdByBytes) {
        return eocdByBytes.value();
    }

    // try to search EOCD with comment
    uint64_t eocdMaxLength = std::min((uint64_t)(EndOfCentralDirectory::EOCD_LENGTH + MAX_COMMENT_LENGTH), fileSize);
    eOCDOffset = (uint64_t)input.tellg() - eocdMaxLength;

    retStr.clear();
    bytes.clear();
    ret = FileUtils::ReadFileByOffsetAndLength(input, eOCDOffset, eocdMaxLength, retStr);
    if (0 != ret) {
        SIGNATURE_TOOLS_LOGE(" ReadFileByOffsetAndLength error");
        return nullptr;
    }
    for (auto item : retStr) {
        bytes.push_back(item);
    }

    for (int start = 0; start < eocdMaxLength; start++) {
        eocdByBytes = EndOfCentralDirectory::GetEOCDByBytes(bytes, start);
        if (eocdByBytes) {
            eOCDOffset += start;
            return eocdByBytes.value();
        }
    }
    SIGNATURE_TOOLS_LOGE("read zip failed: can not find eocd in file");
    return nullptr;
}

bool Zip::GetZipCentralDirectory(std::ifstream& input)
{
    input.seekg(0, std::ios::beg);

    int cDtotal = endOfCentralDirectory->GetcDTotal();
    zipEntries.reserve(cDtotal);
    // read full central directory bytes
    std::string retStr;

    int ret = FileUtils::ReadFileByOffsetAndLength(input, cDOffset, endOfCentralDirectory->GetcDSize(), retStr);
    if (0 != ret) {
        SIGNATURE_TOOLS_LOGE("ReadFileByOffsetAndLength error");
        return false;
    }

    std::vector<char> cdBytes(retStr.begin(), retStr.end());
    if (cdBytes.size() < CentralDirectory::CD_LENGTH) {
        SIGNATURE_TOOLS_LOGE("find zip cd failed");
        return false;
    }

    ByteBuffer bf(cdBytes.data(), cdBytes.size());

    int offset = 0;
    // one by one format central directory
    while (offset < cdBytes.size()) {
        CentralDirectory* cd = new CentralDirectory();
        if (!CentralDirectory::GetCentralDirectory(bf, cd)) {
            SIGNATURE_TOOLS_LOGE("cd is nullptr, get central directory failed.");
            return false;
        }
        ZipEntry* entry = new ZipEntry();
        entry->SetCentralDirectory(cd);
        zipEntries.push_back(entry);
        offset += cd->GetLength();
    }

    if (offset + cDOffset != eOCDOffset) {
        SIGNATURE_TOOLS_LOGE("cd end offset not equals to eocd offset, maybe this is a zip64 file");
        return false;
    }
    return true;
}

std::vector<char> Zip::GetSigningBlock(std::ifstream& file)
{
    uint64_t size = cDOffset - signingOffset;
    if (size < 0) {
        SIGNATURE_TOOLS_LOGE("signing offset in front of entry end");
        return std::vector<char>(0);
    }
    if (size == 0) {
        return std::vector<char>(0);
    }

    std::string retStr;
    std::vector<char> retVec;
    int ret = FileUtils::ReadFileByOffsetAndLength(file, signingOffset, size, retStr);
    if (0 != ret) {
        SIGNATURE_TOOLS_LOGE("ReadFileByOffsetAndLength error");
        return retVec;
    }
    retVec = std::vector<char>(retStr.begin(), retStr.end());
    return retVec;
}

bool Zip::GetZipEntries(std::ifstream& input)
{
    // use central directory data, find entry data
    for (auto entry : zipEntries) {
        CentralDirectory* cd = entry->GetCentralDirectory();
        uint64_t offset = cd->GetOffset();
        uint64_t unCompressedSize = cd->GetUnCompressedSize();
        uint64_t compressedSize = cd->GetCompressedSize();
        uint64_t fileSize = cd->GetMethod() == FILE_UNCOMPRESS_METHOD_FLAG ? unCompressedSize : compressedSize;

        ZipEntryData* zipEntryData = ZipEntryData::GetZipEntry(input, offset, fileSize);
        if (!zipEntryData) {
            SIGNATURE_TOOLS_LOGE("get zip entry data failed.");
            return false;
        }
        if (cDOffset - offset < zipEntryData->GetLength()) {
            SIGNATURE_TOOLS_LOGE("cd offset in front of entry end");
            return false;
        }
        entry->SetZipEntryData(zipEntryData);
    }
    return true;
}

bool Zip::ToFile(std::ifstream& input, std::ofstream& output)
{
    SIGNATURE_TOOLS_LOGI("Zip To File begin");
    if (!input.good()) {
        SIGNATURE_TOOLS_LOGE("read input file failed");
        return false;
    }
    if (!output.good()) {
        SIGNATURE_TOOLS_LOGE("read output file failed");
        return false;
    }
    for (auto& entry : zipEntries) {
        ZipEntryData* zipEntryData = entry->GetZipEntryData();

        std::vector<char> bytesVec = zipEntryData->GetZipEntryHeader()->ToBytes();
        std::string bytesStr(bytesVec.begin(), bytesVec.end());
        if (!FileUtils::WriteByteToOutFile(bytesStr, output)) {
            return false;
        }
    
        long fileOffset = zipEntryData->GetFileOffset();
        long fileSize = zipEntryData->GetFileSize();
        bool isSuccess = FileUtils::AppendWriteFileByOffsetToFile(input, output, fileOffset, fileSize);
        if (!isSuccess) {
            SIGNATURE_TOOLS_LOGE("write zip data failed");
            return false;
        }
        if (zipEntryData->GetDataDescriptor() != nullptr) {
            std::vector<char> bytesVec = zipEntryData->GetDataDescriptor()->ToBytes();
            std::string bytesStr(bytesVec.begin(), bytesVec.end());
            if (!FileUtils::WriteByteToOutFile(bytesStr, output))
                return false;
        }
    }
    if (!signingBlock.empty()) {
        std::string signingBlockStr(signingBlock.begin(), signingBlock.end());
        if (!FileUtils::WriteByteToOutFile(signingBlockStr, output))
            return false;
    }
    for (auto& entry : zipEntries) {
        CentralDirectory* cd = entry->GetCentralDirectory();
        std::vector<char> bytesVec = cd->ToBytes();
        std::string bytesStr(bytesVec.begin(), bytesVec.end());
        if (!FileUtils::WriteByteToOutFile(bytesStr, output))
            return false;
    }

    std::vector<char> endOfCentralDirectoryVec = endOfCentralDirectory->ToBytes();
    std::string endOfCentralDirectoryStr(endOfCentralDirectoryVec.begin(), endOfCentralDirectoryVec.end());
    if (!FileUtils::WriteByteToOutFile(endOfCentralDirectoryStr, output))
        return false;
    SIGNATURE_TOOLS_LOGI("Zip To File end");
    return true;
}

void Zip::Alignment(int alignment)
{
    Sort();
    bool isFirstUnRunnableFile = true;
    for (auto entry : zipEntries) {
        ZipEntryData* zipEntryData = entry->GetZipEntryData();
        short method = zipEntryData->GetZipEntryHeader()->GetMethod();
        if (method != FILE_UNCOMPRESS_METHOD_FLAG && !isFirstUnRunnableFile) {
            // only align uncompressed entry and the first compress entry.
            break;
        }
        int alignBytes;
        if (method == FILE_UNCOMPRESS_METHOD_FLAG &&
            FileUtils::IsRunnableFile(zipEntryData->GetZipEntryHeader()->GetFileName())) {
            // .abc and .so file align 4096 byte.
            alignBytes = 4096;
        } else if (isFirstUnRunnableFile) {
            // the first file after runnable file, align 4096 byte.
            alignBytes = 4096;
            isFirstUnRunnableFile = false;
        } else {
            // normal file align 4 byte.
            alignBytes = alignment;
        }
        int add = entry->Alignment(alignBytes);
        if (add > 0) {
            ResetOffset();
        }
    }
}

void Zip::RemoveSignBlock()
{
    signingBlock = std::vector<char>();
    ResetOffset();
}

void Zip::Sort()
{
    // sort uncompress file (so, abc, an) - other uncompress file - compress file
    std::sort(zipEntries.begin(), zipEntries.end(), [](ZipEntry* entry1, ZipEntry* entry2) {
        short entry1Method = entry1->GetZipEntryData()->GetZipEntryHeader()->GetMethod();
        short entry2Method = entry2->GetZipEntryData()->GetZipEntryHeader()->GetMethod();
        std::string entry1FileName = entry1->GetZipEntryData()->GetZipEntryHeader()->GetFileName();
        std::string entry2FileName = entry2->GetZipEntryData()->GetZipEntryHeader()->GetFileName();
        if (entry1Method == FILE_UNCOMPRESS_METHOD_FLAG && entry2Method == FILE_UNCOMPRESS_METHOD_FLAG) {
            bool isRunnableFile1 = FileUtils::IsRunnableFile(entry1FileName);
            bool isRunnableFile2 = FileUtils::IsRunnableFile(entry2FileName);
            if (isRunnableFile1 && isRunnableFile2) {
                return entry1FileName < entry2FileName;
            } else if (isRunnableFile1) {
                return true;
            } else if (isRunnableFile2) {
                return false;
            }
        } else if (entry1Method == FILE_UNCOMPRESS_METHOD_FLAG) {
            return true;
        } else if (entry2Method == FILE_UNCOMPRESS_METHOD_FLAG) {
            return false;
        }
        return entry1FileName < entry2FileName;
    });
    ResetOffset();
}

void Zip::ResetOffset()
{
    uint64_t offset = 0LL;
    uint64_t cdLength = 0LL;
    for (auto entry : zipEntries) {
        entry->GetCentralDirectory()->SetOffset(offset);
        offset += entry->GetZipEntryData()->GetLength();
        cdLength += entry->GetCentralDirectory()->GetLength();
    }
    if (!signingBlock.empty()) {
        offset += signingBlock.size();
    }
    cDOffset = offset;
    endOfCentralDirectory->SetOffset(offset);
    endOfCentralDirectory->SetcDSize(cdLength);
    offset += cdLength;
    eOCDOffset = offset;
}

std::vector<ZipEntry*>& Zip::GetZipEntries()
{
    return zipEntries;
}

uint64_t Zip::GetSigningOffset()
{
    return signingOffset;
}

uint64_t Zip::GetCDOffset()
{
    return cDOffset;
}

uint64_t Zip::GetEOCDOffset()
{
    return eOCDOffset;
}

EndOfCentralDirectory* Zip::GetEndOfCentralDirectory()
{
    return endOfCentralDirectory;
}
