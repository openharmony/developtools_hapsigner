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

#include "sign_content_info.h"
#include "byte_array_utils.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {
    
SignContentHash::SignContentHash(char type, char tag, short algId, int length, std::vector<int8_t> hash)
{
    this->type = type;
    this->tag = tag;
    this->algId = algId;
    this->length = length;
    this->hash = hash;
    this->contentHashLen = CONTENT_HEAD_SIZE + this->hash.size();
}

SignContentInfo::SignContentInfo()
{
    version = "1000";
    this->size = SignContentHash::CONTENT_HEAD_SIZE;
    numOfBlocks = 0;
}

void SignContentInfo::AddContentHashData(char type, char tag, short algId, int length, std::vector<int8_t> hash)
{
    SignContentHash signInfo(type, tag, algId, length, hash);
    this->AddHashData(signInfo);
}

void SignContentInfo::AddHashData(SignContentHash signInfo)
{
    this->hashData.push_back(signInfo);
    ++numOfBlocks;
    this->size += signInfo.contentHashLen;
}

std::vector<int8_t> SignContentInfo::GetByteContent()
{
    std::vector<int8_t> ret(this->size, 0);
    int index = 0;

    index = ByteArrayUtils::InsertCharToByteArray(ret, index, this->version);
    if (index < 0) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "InsertCharToByteArray failed.");
        return std::vector<int8_t>();
    }

    index = ByteArrayUtils::InsertShortToByteArray(ret, ret.size(), index, size);
    if (index < 0) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "InsertShortToByteArray failed.");
        return std::vector<int8_t>();
    }

    index = ByteArrayUtils::InsertShortToByteArray(ret, ret.size(), index, numOfBlocks);
    if (index < 0) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "InsertShortToByteArray failed.");
        return std::vector<int8_t>();
    }

    for (const auto& tmp : hashData) {
        ret[index] = tmp.type;
        index++;
        ret[index] = tmp.tag;
        index++;
        index = ByteArrayUtils::InsertShortToByteArray(ret, ret.size(), index, tmp.algId);
        index = ByteArrayUtils::InsertIntToByteArray(ret, index, tmp.length);
        index = ByteArrayUtils::InsertByteToByteArray(ret, index, tmp.hash, tmp.hash.size());
        if (index < 0) {
            PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "InsertShortToByteArray failed.");
            return std::vector<int8_t>();
        }
    }
    return ret;
}

} // namespace SignatureTools
} // namespace OHOS