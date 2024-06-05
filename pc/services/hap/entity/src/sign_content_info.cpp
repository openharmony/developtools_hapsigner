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
#include "sign_content_info.h"
#include "byte_array_utils.h"
#include "signature_tools_log.h"

using namespace OHOS::SignatureTools;

SignContentHash::SignContentHash(char type, char tag, short algId, int length, std::vector<int8_t> hash) {
    this->type = type;
    this->tag = tag;
    this->algId = algId;
    this->length = length;
    this->hash = hash;
    this->contentHashLen = CONTENT_HEAD_SIZE + this->hash.size();// ժҪͷ�ĳ���8+Ŀ���ļ�ժҪ�ĳ���32
}

/******************************** SignContentInfo *********************************/
SignContentInfo::SignContentInfo() {
    version = "1000";
    this->size = 8;
    numOfBlocks = 0;
}

void SignContentInfo::AddContentHashData(char type, char tag, short algId, int length, std::vector<int8_t> hash) {
    SignContentHash signInfo(type, tag, algId, length, hash);
    this->AddHashData(signInfo);
}

void SignContentInfo::AddHashData(SignContentHash signInfo) {
    this->hashData.push_back(signInfo);
    ++numOfBlocks;
    this->size += signInfo.contentHashLen;// 8+ժҪͷ�ĳ���8+Ŀ���ļ�ժҪ�ĳ���32
}

std::vector<int8_t> SignContentInfo::GetByteContent() {
    std::vector<int8_t> ret(this->size, 0);
    int index = 0;

    // 1.�Ѱ汾���ַ���"1000"��д���ֽ�����,4���ֽ�
    index = ByteArrayUtils::InsertCharToByteArray(ret, index, this->version);
    if (index < 0) {
        SIGNATURE_TOOLS_LOGE("InsertCharToByteArray failed.\n");
        return std::vector<int8_t>();
    }

    // 2.��[ժҪͷ�ĳ���+Ŀ���ļ�ժҪ�ĳ���]д���ֽ����飬2���ֽ�
    index = ByteArrayUtils::InsertShortToByteArray(ret, ret.size(), index, size);
    if (index < 0) {
        SIGNATURE_TOOLS_LOGE("InsertShortToByteArray failed.\n");
        return std::vector<int8_t>();
    }

    // 3.ǩ���ӿ�ĸ���1д���ֽ����飬2���ֽ�
    index = ByteArrayUtils::InsertShortToByteArray(ret, ret.size(), index, numOfBlocks);
    if (index < 0) {
        SIGNATURE_TOOLS_LOGE("InsertShortToByteArray failed.\n");
        return std::vector<int8_t>();
    }

    for (const auto& tmp : hashData) {
        
        //SignContentHash tmp = hashData.get(i);
        ret[index] = tmp.type; // 4.ǩ���ӿ������0д���ֽ����飬1���ֽ�
        index++;
        ret[index] = tmp.tag; // 5.���λ����Merkletree �ĸ��ڵ� 0x88д���ֽ����飬1���ֽ�
        index++;

        // 6.�㷨idд���ֽ����飬2���ֽ�
        index = ByteArrayUtils::InsertShortToByteArray(ret, ret.size(), index, tmp.algId);
        // 7.Ŀ���ļ�ժҪ�ĳ���д���ֽ����飬4���ֽ�
        index = ByteArrayUtils::InsertIntToByteArray(ret, index, tmp.length);
        // 8.��Ŀ���ļ�ժҪ����д���ֽ�����
        index = ByteArrayUtils::InsertByteToByteArray(ret, index, tmp.hash, tmp.hash.size());
        if (index < 0) {
            SIGNATURE_TOOLS_LOGE("InsertShortToByteArray index invalid.\n");
            return std::vector<int8_t>();
        }
    }
    return ret;
}
