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

#include "sign_block_data.h"

namespace OHOS {
namespace SignatureTools {

SignBlockData::SignBlockData(std::vector<int8_t>& signData, char type)
{
    this->signData = signData;
    this->type = type;
    this->len = signData.size();
    this->isByte = true;
}

SignBlockData::SignBlockData(std::string& signFile, char type)
{
    this->signFile = signFile;
    this->type = type;
    this->len = FileUtils::GetFileLen(signFile);
    this->isByte = false;
}

char SignBlockData::GetType()
{
    return type;
}

void SignBlockData::SetType(char type)
{
    this->type = type;
}

std::vector<int8_t> SignBlockData::GetBlockHead()
{
    return blockHead;
}

void SignBlockData::SetBlockHead(std::vector<int8_t>& blockHead)
{
    this->blockHead = blockHead;
}

std::vector<int8_t> SignBlockData::GetSignData()
{
    return signData;
}

void SignBlockData::SetSignData(std::vector<int8_t>& signData)
{
    this->signData = signData;
}

std::string SignBlockData::GetSignFile()
{
    return signFile;
}

void SignBlockData::SetSignFile(std::string signFile)
{
    this->signFile = signFile;
}

long SignBlockData::GetLen()
{
    return len;
}

bool SignBlockData::GetByte()
{
    return isByte;
}

void SignBlockData::SetLen(long len)
{
    this->len = len;
}

void SignBlockData::SetByte(bool isByte)
{
    this->isByte = isByte;
}

} // namespace SignatureTools
} // namespace OHOS