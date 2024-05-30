#include <fstream>
#include <iostream>
#include "zip_entry_data.h"
#include "file_utils.h"
#include "signature_tools_log.h"

using namespace OHOS::SignatureTools;

ZipEntryHeader *ZipEntryData::GetZipEntryHeader()
{
    return zipEntryHeader;
}

ZipEntryData* ZipEntryData::GetZipEntry(std::ifstream& input, long long entryOffset, long long fileSize)
{
    long long offset = entryOffset;
    // read entry header by file and offset.
    std::string retStr;
    if (FileUtils::ReadInputByOffsetAndLength(input, entryOffset, ZipEntryHeader::HEADER_LENGTH, retStr) != 0) {
        SIGNATURE_TOOLS_LOGE("ReadInputByOffsetAndLength error");
        return nullptr;
    }
    std::vector<char> headBytes(retStr.begin(), retStr.end());
    ZipEntryHeader* entryHeader = ZipEntryHeader::GetZipEntryHeader(headBytes);
    if (!entryHeader) {
        SIGNATURE_TOOLS_LOGE("entry header is nullptr.");
        return nullptr;
    }
    offset += ZipEntryHeader::HEADER_LENGTH;

    // read entry file name and extra by offset.
    if (!ReadEntryFileNameAndExtraByOffset(input, entryHeader, offset)) return nullptr;

    // skip file data , save file offset and size.
    ZipEntryData* entry = new ZipEntryData();
    entry->SetFileOffset(offset);
    entry->SetFileSize(fileSize);
    input.seekg(fileSize, std::ios::cur);
    long long entryLength = entryHeader->GetLength() + fileSize;
    short flag = entryHeader->GetFlag();
    // set desc null flag
    bool hasDesc = (flag & HAS_DATA_DESCRIPTOR_MASK) != NOT_HAS_DATA_DESCRIPTOR_FLAG;
    if (hasDesc) {
        // assuming entry has data descriptor, read entry data descriptor.
        retStr.clear();
        if (FileUtils::ReadInputByLength(input, DataDescriptor::DES_LENGTH, retStr) != 0) {
            SIGNATURE_TOOLS_LOGE("ReadInputByLength error");
            return nullptr;
        }
        std::vector<char> desBytes(retStr.begin(), retStr.end());
        DataDescriptor* dataDesc = DataDescriptor::GetDataDescriptor(desBytes);
        if (!dataDesc) {
            SIGNATURE_TOOLS_LOGE("get data descriptor failed.");
            return nullptr;
        }
        entryLength += DataDescriptor::DES_LENGTH;
        entry->SetDataDescriptor(dataDesc);
    }
    entry->SetZipEntryHeader(entryHeader);
    entry->SetLength(entryLength);
    return entry;
}

bool ZipEntryData::ReadEntryFileNameAndExtraByOffset(std::ifstream &input,
                                                     ZipEntryHeader *entryHeader,
                                                     long long &offset)
{
    if (entryHeader->GetFileNameLength() > 0) {
        std::string fileNameStr;
        if (FileUtils::ReadInputByLength(input, entryHeader->GetFileNameLength(), fileNameStr) != 0) {
            SIGNATURE_TOOLS_LOGE("Read Input By Length ERROR");
            return false;
        }
        std::vector<char> fileNameBytes(fileNameStr.begin(), fileNameStr.end());
        entryHeader->ReadFileName(fileNameBytes);
        offset += entryHeader->GetFileNameLength();
    }
    if (entryHeader->GetExtraLength() > 0) {
        std::string extraStr;
        if (FileUtils::ReadInputByLength(input, entryHeader->GetExtraLength(), extraStr) != 0) {
            SIGNATURE_TOOLS_LOGE("Read Input By Length ERROR");
            return false;
        }
        std::vector<char> extraBytes(extraStr.begin(), extraStr.end());
        entryHeader->ReadExtra(extraBytes);
        offset += entryHeader->GetExtraLength();
    }
    return true;
}

void ZipEntryData::SetZipEntryHeader(ZipEntryHeader *zipEntryHeader)
{
    this->zipEntryHeader = zipEntryHeader;
}

DataDescriptor *ZipEntryData::GetDataDescriptor()
{
    return dataDescriptor;
}

void ZipEntryData::SetDataDescriptor(DataDescriptor *dataDescriptor)
{
    this->dataDescriptor = dataDescriptor;
}

long ZipEntryData::GetFileOffset()
{
    return fileOffset;
}

void ZipEntryData::SetFileOffset(long fileOffset)
{
    this->fileOffset = fileOffset;
}

long ZipEntryData::GetFileSize()
{
    return fileSize;
}

void ZipEntryData::SetFileSize(long fileSize)
{
    this->fileSize = fileSize;
}

long ZipEntryData::GetLength()
{
    return length;
}

void ZipEntryData::SetLength(long length)
{
    this->length = length;
}