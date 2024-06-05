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
#include "fs_verity_digest.h"
using namespace OHOS::SignatureTools;
const std::string FsVerityDigest::FSVERITY_DIGEST_MAGIC = "FSVerity";
const int FsVerityDigest::DIGEST_HEADER_SIZE = 12;
std::vector<int8_t> FsVerityDigest::GetFsVerityDigest(int8_t algoID, std::vector<int8_t>& digest)
{
    int size = DIGEST_HEADER_SIZE + digest.size();
    std::unique_ptr<ByteBuffer> buffer = std::make_unique<ByteBuffer>(ByteBuffer(size));
    buffer->PutData(FSVERITY_DIGEST_MAGIC.c_str(), (int32_t)FSVERITY_DIGEST_MAGIC.length());
    buffer->PutInt16(algoID);
    buffer->PutInt16((int16_t)digest.size());
    buffer->PutData((char*)digest.data(), digest.size());
    buffer->Flip();
    char* dataArr = new char[size];
    buffer->GetData(dataArr, size);
    std::vector<int8_t> ret(dataArr, dataArr + size);
    delete[] dataArr;
    return ret;
}