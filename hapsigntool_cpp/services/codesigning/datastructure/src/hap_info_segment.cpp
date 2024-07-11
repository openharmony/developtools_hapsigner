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
#include "hap_info_segment.h"

namespace OHOS {
namespace SignatureTools {

HapInfoSegment::HapInfoSegment()
{
    std::vector<int8_t> emptyVector;
    magic = HapInfoSegment::MAGIC_NUM;
    signInfo = SignInfo(0, 0, 0, emptyVector, emptyVector);
}

HapInfoSegment::HapInfoSegment(int32_t magic, SignInfo signInfo)
{
    this->magic = magic;
    this->signInfo = signInfo;
}

void HapInfoSegment::SetSignInfo(SignInfo signInfo)
{
    this->signInfo = signInfo;
}

SignInfo& HapInfoSegment::GetSignInfo()
{
    return signInfo;
}

int32_t HapInfoSegment::GetSize()
{
    return HapInfoSegment::MAGIC_NUM_BYTES + signInfo.GetSize();
}

void HapInfoSegment::ToByteArray(std::vector<int8_t> &ret)
{
    std::vector<int8_t> hapSignInfoByteArray;
    signInfo.ToByteArray(hapSignInfoByteArray);
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>
        (ByteBuffer(HapInfoSegment::MAGIC_NUM_BYTES + hapSignInfoByteArray.size()));
    bf->PutInt32(magic);
    bf->PutData(hapSignInfoByteArray.data(), hapSignInfoByteArray.size());
    ret = std::vector<int8_t>(bf->GetBufferPtr(), bf->GetBufferPtr() + bf->GetPosition());
    return;
}

HapInfoSegment HapInfoSegment::FromByteArray(std::vector<int8_t> bytes)
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(bytes.size()));
    bf->PutData(bytes.data(), bytes.size());
    bf->Flip();
    int32_t inMagic = 0;
    bf->GetInt32(inMagic);
    if (inMagic != HapInfoSegment::MAGIC_NUM) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid magic number of HapInfoSegment");
        return HapInfoSegment();
    }
    if (bytes.size() <= HapInfoSegment::MAGIC_NUM_BYTES) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid bytes size of HapInfoSegment");
        return HapInfoSegment();
    }
    std::vector<int8_t> hapSignInfoByteArray(bytes.size() - HapInfoSegment::MAGIC_NUM_BYTES);
    bf->GetByte(hapSignInfoByteArray.data(), hapSignInfoByteArray.size());
    SignInfo inHapSignInfo = SignInfo::FromByteArray(hapSignInfoByteArray);
    if (inHapSignInfo.GetDataSize() % HapInfoSegment::CHUNK_SIZE != 0) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR,
                            "Invalid dataSize number of HapInfoSegment, not a multiple of 4096");
        return HapInfoSegment();
    }
    if (inHapSignInfo.GetExtensionNum() != SignInfo::MAX_EXTENSION_NUM) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Invalid extensionNum of HapInfoSegment");
        return HapInfoSegment();
    }
    return HapInfoSegment(inMagic, inHapSignInfo);
}

}
}