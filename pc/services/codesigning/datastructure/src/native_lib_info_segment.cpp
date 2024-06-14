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
#include "native_lib_info_segment.h"

namespace OHOS {
namespace SignatureTools {

NativeLibInfoSegment::NativeLibInfoSegment()
{
    this->magic = MAGIC_NUM;
    this->zeroPadding = std::vector<int8_t>(0);
}

NativeLibInfoSegment::NativeLibInfoSegment(int32_t magic,
                                           int32_t segmentSize,
                                           int32_t sectionNum,
                                           std::vector<SignedFilePos> signedFilePosList,
                                           std::vector<std::string> fileNameList,
                                           std::vector<SignInfo> signInfoList,
                                           std::vector<int8_t> zeroPadding
)
{
    this->magic = magic;
    this->segmentSize = segmentSize;
    this->sectionNum = sectionNum;
    this->signedFilePosList = signedFilePosList;
    this->fileNameList = fileNameList;
    this->signInfoList = signInfoList;
    this->zeroPadding = zeroPadding;
}

void NativeLibInfoSegment::SetSoInfoList(std::vector<std::pair<std::string, SignInfo>> soInfoList)
{
    this->soInfoList = soInfoList;
    // Once map is set, update length, sectionNum as well
    this->sectionNum = soInfoList.size();
    // generate file name list and sign info list
    GenerateList();
}

int32_t NativeLibInfoSegment::GetSectionNum()
{
    return sectionNum;
}

std::vector<std::string> NativeLibInfoSegment::GetFileNameList()
{
    return fileNameList;
}

std::vector<OHOS::SignatureTools::SignInfo> NativeLibInfoSegment::GetSignInfoList()
{
    return signInfoList;
}

int32_t NativeLibInfoSegment::Size()
{
    int blockSize = MAGIC_LENGTH_SECNUM_BYTES;
    blockSize += signedFilePosList.size() * SIGNED_FILE_POS_SIZE;
    blockSize += this->fileNameListBlockSize + this->zeroPadding.size() + this->signInfoListBlockSize;
    return blockSize;
}

std::vector<int8_t> NativeLibInfoSegment::ToByteArray()
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(this->Size()));
    std::vector<int8_t> empt(this->Size());
    bf->PutData(empt.data(), empt.size());
    bf->Clear();
    bf->PutInt32(magic);
    bf->PutInt32(segmentSize);
    bf->PutInt32(sectionNum);
    for (SignedFilePos offsetAndSize : this->signedFilePosList) {
        bf->PutInt32(offsetAndSize.GetFileNameOffset());
        bf->PutInt32(offsetAndSize.GetFileNameSize());
        bf->PutInt32(offsetAndSize.GetSignInfoOffset());
        bf->PutInt32(offsetAndSize.GetSignInfoSize());
    }
    for (std::string fileName : fileNameList) {
        bf->PutData(fileName.c_str(), fileName.size() * sizeof(char));
    }
    bf->PutData(this->zeroPadding.data(), this->zeroPadding.size());
    for (SignInfo signInfo : signInfoList) {
        std::vector<int8_t> signInfoArr = signInfo.ToByteArray();
        bf->PutData(signInfoArr.data(), signInfoArr.size());
    }
    std::vector<int8_t> ret(bf->GetBufferPtr(), bf->GetBufferPtr() + bf->GetPosition());
    return ret;
}

NativeLibInfoSegment NativeLibInfoSegment::FromByteArray(std::vector<int8_t> bytes)
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(bytes.size()));
    bf->PutData(bytes.data(), bytes.size());
    bf->Flip();
    int32_t inMagic = 0;
    bf->GetInt32(inMagic);
    if (inMagic != MAGIC_NUM) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid magic number of NativeLibInfoSegment");
        return NativeLibInfoSegment();
    }
    int32_t inSegmentSize = 0;
    bf->GetInt32(inSegmentSize);
    if (inSegmentSize < 0) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid segmentSize of NativeLibInfoSegment");
        return NativeLibInfoSegment();
    }
    int32_t inSectionNum = 0;
    bf->GetInt32(inSectionNum);
    if (inSectionNum < 0) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid sectionNum of NativeLibInfoSegment");
        return NativeLibInfoSegment();
    }
    std::vector<SignedFilePos> inSignedFilePosList;
    for (int i = 0; i < inSectionNum; i++) {
        std::vector<int8_t> entry(SIGNED_FILE_POS_SIZE, 0);
        bf->GetByte(entry.data(), entry.size());
        inSignedFilePosList.push_back(SignedFilePos::FromByteArray(entry));
    }
    // parse file name list
    std::vector<std::string> inFileNameList;
    int fileNameListSize = 0;
    for (SignedFilePos pos : inSignedFilePosList) {
        std::vector<char> fileNameBuffer(pos.GetFileNameSize(), 0);
        fileNameListSize += pos.GetFileNameSize();
        bf->GetData(fileNameBuffer.data(), fileNameBuffer.size());
        inFileNameList.push_back(std::string(fileNameBuffer.data(), fileNameBuffer.size()));
    }
    // parse zeroPadding
    std::vector<int8_t> inZeroPadding((ALIGNMENT_FOR_SIGNINFO - fileNameListSize
                                      % ALIGNMENT_FOR_SIGNINFO) % ALIGNMENT_FOR_SIGNINFO);
    bf->GetByte(inZeroPadding.data(), inZeroPadding.size());
    // parse sign info list
    std::vector<OHOS::SignatureTools::SignInfo> inSignInfoList;
    for (SignedFilePos pos : inSignedFilePosList) {
        if (pos.GetSignInfoOffset() % ALIGNMENT_FOR_SIGNINFO != 0) {
            PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "SignInfo not aligned in NativeLibInfoSegment");
            return NativeLibInfoSegment();
        }
        std::vector<int8_t> signInfoBuffer(pos.GetSignInfoSize());
        bf->GetByte(signInfoBuffer.data(), signInfoBuffer.size());
        inSignInfoList.push_back(OHOS::SignatureTools::SignInfo::FromByteArray(signInfoBuffer));
    }
    return NativeLibInfoSegment(inMagic, inSegmentSize, inSectionNum, inSignedFilePosList,
                                inFileNameList, inSignInfoList, inZeroPadding);
}

void NativeLibInfoSegment::GenerateList()
{
    // empty all before generate list
    this->fileNameList.clear();
    this->signInfoList.clear();
    this->signedFilePosList.clear();
    int fileNameOffset = 0;
    int signInfoOffset = 0;
    for (std::pair<std::string, SignInfo> soInfo :soInfoList) {
        std::string fileName = soInfo.first;
        SignInfo& signInfo = soInfo.second;
        int fileNameSizeInBytes = fileName.size() * sizeof(char);
        int signInfoSizeInBytes = signInfo.GetSize() * sizeof(char);
        this->fileNameList.push_back(fileName);
        this->signInfoList.push_back(signInfo);
        std::unique_ptr<SignedFilePos> posPtr = std::make_unique<SignedFilePos>(fileNameOffset,
            fileNameSizeInBytes, signInfoOffset, signInfoSizeInBytes);
        this->signedFilePosList.push_back(*posPtr.get());
        // increase fileNameOffset and signInfoOffset
        fileNameOffset += fileNameSizeInBytes;
        signInfoOffset += signInfoSizeInBytes;
    }
    this->fileNameListBlockSize = fileNameOffset;
    this->signInfoListBlockSize = signInfoOffset;
    // alignment for signInfo
    this->zeroPadding = std::vector<int8_t>((ALIGNMENT_FOR_SIGNINFO - this->fileNameListBlockSize
                                            % ALIGNMENT_FOR_SIGNINFO) % ALIGNMENT_FOR_SIGNINFO);
    // after fileNameList and signInfoList is generated, update segment size
    this->segmentSize = this->Size();
    // adjust file name and sign info offset base on segment start
    int fileNameOffsetBase = MAGIC_LENGTH_SECNUM_BYTES + signedFilePosList.size() * SIGNED_FILE_POS_SIZE;
    int signInfoOffsetBase = fileNameOffsetBase + this->fileNameListBlockSize;
    for (SignedFilePos pos : this->signedFilePosList) {
        pos.IncreaseFileNameOffset(fileNameOffsetBase);
        pos.IncreaseSignInfoOffset(signInfoOffsetBase + this->zeroPadding.size());
    }
}

}
}