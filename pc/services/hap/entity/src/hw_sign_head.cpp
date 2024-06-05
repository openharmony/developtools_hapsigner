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
#include <vector>
#include "byte_buffer.h"
#include "hw_sign_head.h"
#include "byte_array_utils.h"
#include "signature_tools_log.h"

using namespace OHOS::SignatureTools;

const int HwSignHead::SIGN_HEAD_LEN = 32;
const std::string HwSignHead::MAGIC = "hw signed app   ";
const std::string HwSignHead::ELF_MAGIC = "elf sign block  ";
const std::string HwSignHead::VERSION = "1000";
const int HwSignHead::NUM_OF_BLOCK = 2;
const int HwSignHead::RESERVE_LENGTH = 4;
const int32_t HwSignHead::ELF_BLOCK_LEN = 12;
const int32_t HwSignHead::BIN_BLOCK_LEN = 8;
std::vector<int8_t> HwSignHead::reserve = std::vector<int8_t>(HwSignHead::RESERVE_LENGTH, 0);

HwSignHead::HwSignHead() { 

}

std::vector<int8_t> HwSignHead::GetSignHead(int subBlockSize)
{
    int size = subBlockSize;
    std::vector<int8_t> signHead(SIGN_HEAD_LEN, 0);
    int start = 0;
    start = ByteArrayUtils::InsertCharToByteArray(signHead, start, MAGIC);
    if (start < 0) {
        SIGNATURE_TOOLS_LOGW("InsertCharToByteArray failed.\n");
        return std::vector<int8_t>();
    }
    start = ByteArrayUtils::InsertCharToByteArray(signHead, start, VERSION);
    if (start < 0) {
        SIGNATURE_TOOLS_LOGW("InsertCharToByteArray failed.\n");
        return std::vector<int8_t>();
    }
    start = ByteArrayUtils::InsertIntToByteArray(signHead, start, size);
    if (start < 0) {
        SIGNATURE_TOOLS_LOGW("InsertIntToByteArray failed.\n");
        return std::vector<int8_t>();
    }
    start = ByteArrayUtils::InsertIntToByteArray(signHead, start, NUM_OF_BLOCK);
    if (start < 0) {
        SIGNATURE_TOOLS_LOGW("InsertIntToByteArray failed.\n");
        return std::vector<int8_t>();
    }
    start = ByteArrayUtils::InsertCharToByteArray(signHead, start, std::string(reserve.begin(), reserve.end()));
    if (start < 0) {
        SIGNATURE_TOOLS_LOGW("InsertCharToByteArray failed.\n");
        return std::vector<int8_t>();
    }
    return signHead;
}
std::vector<int8_t> HwSignHead::getSignHeadLittleEndian(int subBlockSize, int subBlockNum)
{
    ByteBuffer bf = ByteBuffer(HwSignHead::SIGN_HEAD_LEN);
    for (char c : HwSignHead::ELF_MAGIC)
    {
        bf.PutByte(c);
    }
    for (char c : HwSignHead::VERSION)
    {
        bf.PutByte(c);
    }
    bf.PutInt32(subBlockSize);
    bf.PutInt32(subBlockNum);
    for (char c : HwSignHead::reserve)
    {
        bf.PutByte(c);
    }
    int8_t ret[HwSignHead::SIGN_HEAD_LEN];
    bf.GetData(0, (char *)&ret, HwSignHead::SIGN_HEAD_LEN);
    std::vector<int8_t> byte(ret, ret + HwSignHead::SIGN_HEAD_LEN);

    return byte;
}