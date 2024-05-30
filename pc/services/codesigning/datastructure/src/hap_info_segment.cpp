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
#include "hap_info_segment.h"
using namespace OHOS::SignatureTools;
const int32_t HapInfoSegment::MAGIC_NUM_BYTES = 4;
const int32_t HapInfoSegment::CHUNK_SIZE = 4096;
const int32_t HapInfoSegment::MAGIC_NUM = (0xC1B5 << 16) + 0xCC66;
HapInfoSegment::HapInfoSegment()
{
    std::vector<int8_t> emptyVector;
    this->magic = HapInfoSegment::MAGIC_NUM;
    this->signInfo = SignInfo(0, 0, 0, emptyVector, emptyVector);
}
HapInfoSegment::HapInfoSegment(int32_t magic, SignInfo signInfo)
{
    this->magic = magic;
    this->signInfo = signInfo;
}
void HapInfoSegment::setSignInfo(SignInfo signInfo)
{
    this->signInfo = signInfo;
}
SignInfo& HapInfoSegment::getSignInfo()
{
    return signInfo;
}
int32_t HapInfoSegment::getSize()
{
    return HapInfoSegment::MAGIC_NUM_BYTES + signInfo.getSize();
}
std::vector<int8_t> HapInfoSegment::toByteArray()
{
    std::vector<int8_t> hapSignInfoByteArray = this->signInfo.toByteArray();
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>
        (ByteBuffer(HapInfoSegment::MAGIC_NUM_BYTES + hapSignInfoByteArray.size()));
    bf->PutInt32(magic);
    bf->PutData((char*)hapSignInfoByteArray.data(), hapSignInfoByteArray.size());
    std::vector<int8_t> ret(bf->GetBufferPtr(), bf->GetBufferPtr() + bf->GetPosition());
    return ret;
}
HapInfoSegment HapInfoSegment::fromByteArray(std::vector<int8_t> bytes)
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(bytes.size()));
    bf->PutData((char*)bytes.data(), bytes.size());
    bf->Flip();
    int32_t inMagic = 0;
    bf->GetInt32(inMagic);
    if (inMagic != HapInfoSegment::MAGIC_NUM) {
        SIGNATURE_TOOLS_LOGE("Invalid magic number of HapInfoSegment");
        return HapInfoSegment();
    }
    if (bytes.size() <= HapInfoSegment::MAGIC_NUM_BYTES) {
        SIGNATURE_TOOLS_LOGE("Invalid bytes size of HapInfoSegment");
        return HapInfoSegment();
    }
    std::vector<int8_t> hapSignInfoByteArray(bytes.size() - HapInfoSegment::MAGIC_NUM_BYTES);
    bf->GetData((char*)hapSignInfoByteArray.data(), hapSignInfoByteArray.size());
    SignInfo inHapSignInfo = SignInfo::fromByteArray(hapSignInfoByteArray);
    if (inHapSignInfo.getDataSize() % HapInfoSegment::CHUNK_SIZE != 0) {
        SIGNATURE_TOOLS_LOGE("Invalid dataSize number of HapInfoSegment, not a multiple of 4096");
        return HapInfoSegment();
    }
    if (inHapSignInfo.getExtensionNum() != SignInfo::MAX_EXTENSION_NUM) {
        SIGNATURE_TOOLS_LOGE("Invalid extensionNum of HapInfoSegment");
        return HapInfoSegment();
    }
    return HapInfoSegment(inMagic, inHapSignInfo);
}