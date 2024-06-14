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

#include "unsigned_decimal_util.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {
int64_t UnsignedDecimalUtil::GetUnsignedInt(ByteBuffer& bf)
{
    uint32_t value;
    bf.GetUInt32(value);
    return value & MAX_UNSIGNED_INT_VALUE;
}

int UnsignedDecimalUtil::GetUnsignedShort(ByteBuffer& bf)
{
    uint16_t value;
    bf.GetUInt16(value);
    return value & MAX_UNSIGNED_SHORT_VALUE;
}

void UnsignedDecimalUtil::SetUnsignedInt(ByteBuffer& bf, int64_t value)
{
    std::string bytes = {
        static_cast<char>(value & 0xFF),
        static_cast<char>((value >> BIT_SIZE) & 0xFF),
        static_cast<char>((value >> DOUBLE_BIT_SIZE) & 0xFF),
        static_cast<char>((value >> TRIPLE_BIT_SIZE) & 0xFF)
    };
    bf.PutData(bytes.c_str(), bytes.size());
}

void UnsignedDecimalUtil::SetUnsignedShort(ByteBuffer& bf, int value)
{
    std::string bytes = {
        static_cast<signed char>(value & 0xFF),
        static_cast<signed char>((value >> BIT_SIZE) & 0xFF)
    };
    bf.PutData(bytes.c_str(), bytes.size());
}
} // namespace SignatureTools
} // namespace OHOS