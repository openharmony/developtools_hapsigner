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
#include "signed_file_pos.h"
using namespace OHOS::SignatureTools;
SignedFilePos::SignedFilePos(int32_t fileNameOffset,
    int32_t fileNameSize,
    int32_t signInfoOffset,
    int32_t signInfoSize)
    :fileNameOffset(fileNameOffset),
    fileNameSize(fileNameSize),
    signInfoOffset(signInfoOffset),
    signInfoSize(signInfoSize)
{
}
int32_t SignedFilePos::getFileNameOffset()
{
    return fileNameOffset;
}
int32_t SignedFilePos::getFileNameSize()
{
    return fileNameSize;
}
int32_t SignedFilePos::getSignInfoOffset()
{
    return signInfoOffset;
}
int32_t SignedFilePos::getSignInfoSize()
{
    return signInfoSize;
}
void SignedFilePos::increaseFileNameOffset(int32_t incOffset)
{
    this->fileNameOffset += incOffset;
}
void SignedFilePos::increaseSignInfoOffset(int32_t incOffset)
{
    this->signInfoOffset += incOffset;
}
SignedFilePos SignedFilePos::fromByteArray(std::vector<int8_t> bytes)
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(bytes.size()));
    bf->PutData(0, (char*)bytes.data(), bytes.size());
    int32_t inFileNameOffset = 0;
    bf->GetInt32(inFileNameOffset);
    int32_t inFileNameSize = 0;
    bf->GetInt32(inFileNameSize);
    int32_t inSignInfoOffset = 0;
    bf->GetInt32(inSignInfoOffset);
    int32_t inSignInfoSize = 0;
    bf->GetInt32(inSignInfoSize);
    return SignedFilePos(inFileNameOffset, inFileNameSize, inSignInfoOffset, inSignInfoSize);
}