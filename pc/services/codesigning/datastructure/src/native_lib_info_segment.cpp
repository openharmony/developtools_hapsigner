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
#include "native_lib_info_segment.h"
using namespace OHOS::SignatureTools;
/*********** NativeLibInfoSegment类 **************/
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
void NativeLibInfoSegment::setSoInfoList(std::vector<std::pair<std::string, SignInfo>> soInfoList)
{
    this->soInfoList = soInfoList;
    // Once map is set, update length, sectionNum as well
    this->sectionNum = soInfoList.size();
    // generate file name list and sign info list
    generateList();
}
int32_t NativeLibInfoSegment::getSectionNum()
{
    return sectionNum;
}
std::vector<std::string> NativeLibInfoSegment::getFileNameList()
{
    return fileNameList;
}
std::vector<OHOS::SignatureTools::SignInfo> NativeLibInfoSegment::getSignInfoList()
{
    return signInfoList;
}
int32_t NativeLibInfoSegment::size()
{
    int blockSize = MAGIC_LENGTH_SECNUM_BYTES;
    blockSize += signedFilePosList.size() * SIGNED_FILE_POS_SIZE;
    blockSize += this->fileNameListBlockSize + this->zeroPadding.size() + this->signInfoListBlockSize;
    return blockSize;
}
std::vector<int8_t> NativeLibInfoSegment::toByteArray()
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(this->size()));
    std::vector<int8_t> empt(this->size());
    bf->PutData((char*)empt.data(), empt.size());
    bf->Clear();
    bf->PutInt32(magic);
    bf->PutInt32(segmentSize);
    bf->PutInt32(sectionNum);
    for (SignedFilePos offsetAndSize : this->signedFilePosList) {
        bf->PutInt32(offsetAndSize.getFileNameOffset());
        bf->PutInt32(offsetAndSize.getFileNameSize());
        bf->PutInt32(offsetAndSize.getSignInfoOffset());
        bf->PutInt32(offsetAndSize.getSignInfoSize());
    }
    for (std::string fileName : fileNameList) {
        bf->PutData(fileName.c_str(), fileName.size() * sizeof(char));
    }
    bf->PutData((char*)this->zeroPadding.data(), this->zeroPadding.size());
    for (SignInfo signInfo : signInfoList) {
        std::vector<int8_t> signInfoArr = signInfo.toByteArray();
        bf->PutData((char*)signInfoArr.data(), signInfoArr.size());
    }
    std::vector<int8_t> ret(bf->GetBufferPtr(), bf->GetBufferPtr() + bf->GetPosition());
    return ret;
}
NativeLibInfoSegment NativeLibInfoSegment::fromByteArray(std::vector<int8_t> bytes)
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(bytes.size()));
    bf->PutData((char*)bytes.data(), bytes.size());
    bf->Flip();
    int32_t inMagic = 0;
    bf->GetInt32(inMagic);
    if (inMagic != MAGIC_NUM) {
        SIGNATURE_TOOLS_LOGE("Invalid magic number of NativeLibInfoSegment");
        return NativeLibInfoSegment();
    }
    int32_t inSegmentSize = 0;
    bf->GetInt32(inSegmentSize);
    if (inSegmentSize < 0) {
        SIGNATURE_TOOLS_LOGE("Invalid segmentSize of NativeLibInfoSegment");
        return NativeLibInfoSegment();
    }
    int32_t inSectionNum = 0;
    bf->GetInt32(inSectionNum);
    if (inSectionNum < 0) {
        SIGNATURE_TOOLS_LOGE("Invalid sectionNum of NativeLibInfoSegment");
        return NativeLibInfoSegment();
    }
    std::vector<SignedFilePos> inSignedFilePosList;
    for (int i = 0; i < inSectionNum; i++) {
        std::vector<int8_t> entry(SIGNED_FILE_POS_SIZE, 0);
        bf->GetData((char*)entry.data(), entry.size());
        inSignedFilePosList.push_back(SignedFilePos::fromByteArray(entry));
    }
    // parse file name list
    std::vector<std::string> inFileNameList;
    int fileNameListSize = 0;
    for (SignedFilePos pos : inSignedFilePosList) {
        std::vector<char> fileNameBuffer(pos.getFileNameSize(), 0);
        fileNameListSize += pos.getFileNameSize();
        bf->GetData((char*)fileNameBuffer.data(), fileNameBuffer.size());
        inFileNameList.push_back(std::string(fileNameBuffer.data(), fileNameBuffer.size()));
    }
    // parse zeroPadding
    std::vector<int8_t> inZeroPadding((ALIGNMENT_FOR_SIGNINFO - fileNameListSize
        % ALIGNMENT_FOR_SIGNINFO) % ALIGNMENT_FOR_SIGNINFO);
    bf->GetData((char*)inZeroPadding.data(), inZeroPadding.size());
    // parse sign info list
    std::vector<OHOS::SignatureTools::SignInfo> inSignInfoList;
    for (SignedFilePos pos : inSignedFilePosList) {
        if (pos.getSignInfoOffset() % ALIGNMENT_FOR_SIGNINFO != 0) {
            SIGNATURE_TOOLS_LOGE("SignInfo not aligned in NativeLibInfoSegment");
            return NativeLibInfoSegment();
        }
        std::vector<int8_t> signInfoBuffer(pos.getSignInfoSize());
        bf->GetData((char*)signInfoBuffer.data(), signInfoBuffer.size());
        inSignInfoList.push_back(OHOS::SignatureTools::SignInfo::fromByteArray(signInfoBuffer));
    }
    return NativeLibInfoSegment(inMagic, inSegmentSize, inSectionNum, inSignedFilePosList,
        inFileNameList, inSignInfoList, inZeroPadding);
}
void NativeLibInfoSegment::generateList()
{
    // empty all before generate list
    this->fileNameList.clear();
    this->signInfoList.clear();
    this->signedFilePosList.clear();
    int fileNameOffset = 0;
    int signInfoOffset = 0;
    for (std::pair<std::string, SignInfo> soInfo : soInfoList) {
        std::string fileName = soInfo.first;
        SignInfo& signInfo = soInfo.second;
        int fileNameSizeInBytes = fileName.size() * sizeof(char);
        int signInfoSizeInBytes = signInfo.getSize() * sizeof(char);
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
    this->segmentSize = this->size();
    // adjust file name and sign info offset base on segment start
    int fileNameOffsetBase = MAGIC_LENGTH_SECNUM_BYTES + signedFilePosList.size() * SIGNED_FILE_POS_SIZE;
    int signInfoOffsetBase = fileNameOffsetBase + this->fileNameListBlockSize;
    for (SignedFilePos pos : this->signedFilePosList) {
        pos.increaseFileNameOffset(fileNameOffsetBase);
        pos.increaseSignInfoOffset(signInfoOffsetBase + this->zeroPadding.size());
    }
}