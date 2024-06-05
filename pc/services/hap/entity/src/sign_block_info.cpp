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

#include "sign_block_info.h"

using namespace OHOS::SignatureTools;

SignBlockInfo::SignBlockInfo()
{

}

SignBlockInfo::SignBlockInfo(bool needGenerateDigest)
{
    this->needGenerateDigest = needGenerateDigest;
}

std::unordered_map<signed char, SigningBlock>& SignBlockInfo::GetSignBlockMap()
{
    return signBlockMap;
}

void SignBlockInfo::SetSignBlockMap(std::unordered_map<signed char, SigningBlock>& signBlockMap)
{
    this->signBlockMap = signBlockMap;
}

std::vector<int8_t> SignBlockInfo::GetFileDigest()
{
    return fileDigest;
}

void SignBlockInfo::SetFileDigest(std::vector<int8_t> fileDigest)
{
    this->fileDigest = fileDigest;
}

std::vector<int8_t> SignBlockInfo::GetRawDigest()
{
    return rawDigest;
}

void SignBlockInfo::SetRawDigest(std::vector<int8_t> rawDigest)
{
    this->rawDigest = rawDigest;
}

bool SignBlockInfo::GetNeedGenerateDigest()
{
    return needGenerateDigest;
}

void SignBlockInfo::SetNeedGenerateDigest(bool needGenerateDigest)
{
    this->needGenerateDigest = needGenerateDigest;
}