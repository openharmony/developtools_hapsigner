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

#include "fs_verity_descriptor_with_sign.h"

namespace OHOS {
namespace SignatureTools {
const int32_t FsVerityDescriptorWithSign::INTEGER_BYTES = 4;

FsVerityDescriptorWithSign::FsVerityDescriptorWithSign()
{}

FsVerityDescriptorWithSign::FsVerityDescriptorWithSign(FsVerityDescriptor fsVerityDescriptor,
    std::vector<int8_t> signature)
{
    this->fsVerityDescriptor = fsVerityDescriptor;
    if (!signature.empty()) {
        this->signature = signature;
    }
    this->length = FsVerityDescriptor::DESCRIPTOR_SIZE + this->signature.size();
}

FsVerityDescriptorWithSign::FsVerityDescriptorWithSign(int32_t type, int32_t length,
    FsVerityDescriptor fsVerityDescriptor, std::vector<int8_t> signature)
{
    this->type = type;
    this->length = length;
    this->fsVerityDescriptor = fsVerityDescriptor;
    this->signature = signature;
}

int32_t FsVerityDescriptorWithSign::Size()
{
    int tmp_variable = 2;
    return INTEGER_BYTES * tmp_variable + FsVerityDescriptor::DESCRIPTOR_SIZE + this->signature.size();
}

std::vector<int8_t> FsVerityDescriptorWithSign::ToByteArray()
{
    std::shared_ptr<ByteBuffer> buffer = std::make_shared<ByteBuffer>(Size());
    buffer->PutInt32(this->type);
    buffer->PutInt32(this->length);
    std::vector<int8_t> fsArr = this->fsVerityDescriptor.ToByteArray();
    buffer->PutData(fsArr.data(), fsArr.size());
    buffer->PutData(this->signature.data(), this->signature.size());
    buffer->Flip();
    std::vector<int8_t> ret(buffer->GetBufferPtr(), buffer->GetBufferPtr() + buffer->GetLimit());
    return ret;
}

FsVerityDescriptor FsVerityDescriptorWithSign::GetFsVerityDescriptor()
{
    return fsVerityDescriptor;
}

std::vector<int8_t> FsVerityDescriptorWithSign::GetSignature()
{
    return signature;
}
} // namespace SignatureTools
} // namespace OHOS