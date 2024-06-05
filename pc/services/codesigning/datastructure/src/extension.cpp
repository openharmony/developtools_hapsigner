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
#include "extension.h"
#include "byte_buffer.h"
using namespace OHOS::SignatureTools;
const int32_t Extension::EXTENSION_HEADER_SIZE = 8;
Extension::Extension()
{
    this->type = 0;
    this->size = 0;
}
Extension::Extension(int32_t type, int32_t size)
{
    this->type = type;
    this->size = size;
}
Extension::~Extension()
{
}
int32_t Extension::getSize()
{
    return Extension::EXTENSION_HEADER_SIZE;
}
bool Extension::isType(int32_t type)
{
    return this->type == type;
}
std::vector<int8_t> Extension::toByteArray()
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>
        (ByteBuffer(Extension::EXTENSION_HEADER_SIZE));
    bf->PutInt32(this->type);
    bf->PutInt32(this->size);
    bf->Flip();
    char dataArr[Extension::EXTENSION_HEADER_SIZE] = { 0 };
    bf->GetData(dataArr, Extension::EXTENSION_HEADER_SIZE);
    std::vector<int8_t> ret(dataArr, dataArr + Extension::EXTENSION_HEADER_SIZE);
    return ret;
}
std::string Extension::toString()
{
    std::string str = "Extension: type[" + std::to_string(this->type) + "], size[" + std::to_string(this->size) + "]";
    return str;
}