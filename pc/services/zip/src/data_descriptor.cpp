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

#include "data_descriptor.h"
#include "signature_tools_log.h"
#include "unsigned_decimal_util.h"

namespace OHOS {
namespace SignatureTools {
DataDescriptor* DataDescriptor::GetDataDescriptor(const std::string& bytes)
{
    if (bytes.size() != DES_LENGTH) {
        SIGNATURE_TOOLS_LOGE("read Data Descriptor failed");
        return nullptr;
    }

    ByteBuffer bf(bytes.c_str(), bytes.size());

    DataDescriptor* data = new DataDescriptor();
    int signValue;
    bf.GetInt32(signValue);
    if (signValue != SIGNATURE) {
        delete data;
        SIGNATURE_TOOLS_LOGE("read Data Descriptor failed");
        return nullptr;
    }
    int crc2Value;
    bf.GetInt32(crc2Value);
    data->SetCrc32(crc2Value);
    data->SetCompressedSize(UnsignedDecimalUtil::GetUnsignedInt(bf));
    data->SetUnCompressedSize(UnsignedDecimalUtil::GetUnsignedInt(bf));

    return data;
}

std::string DataDescriptor::ToBytes()
{
    ByteBuffer bf(DES_LENGTH);
    bf.PutInt32(SIGNATURE);
    bf.PutInt32(crc32);
    UnsignedDecimalUtil::SetUnsignedInt(bf, compressedSize);
    UnsignedDecimalUtil::SetUnsignedInt(bf, unCompressedSize);

    return bf.ToString();
}

int DataDescriptor::GetDesLength()
{
    return DES_LENGTH;
}

int DataDescriptor::GetSIGNATURE()
{
    return SIGNATURE;
}

int DataDescriptor::GetCrc32()
{
    return crc32;
}

void DataDescriptor::SetCrc32(int crc32)
{
    this->crc32 = crc32;
}

int64_t DataDescriptor::GetCompressedSize()
{
    return compressedSize;
}

void DataDescriptor::SetCompressedSize(int64_t compressedSize)
{
    this->compressedSize = compressedSize;
}

int64_t DataDescriptor::GetUnCompressedSize()
{
    return unCompressedSize;
}

void DataDescriptor::SetUnCompressedSize(int64_t unCompressedSize)
{
    this->unCompressedSize = unCompressedSize;
}
} // namespace SignatureTools
} // namespace OHOS