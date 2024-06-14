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

#ifndef SIGNATRUETOOLS_UNSIGNED_DECIMAL_UTIL_H
#define SIGNATRUETOOLS_UNSIGNED_DECIMAL_UTIL_H

#include "byte_buffer.h"

namespace OHOS {
namespace SignatureTools {
class UnsignedDecimalUtil {
public:
    /* max unsigned int value */
    static constexpr int64_t MAX_UNSIGNED_INT_VALUE = 0xFFFFFFFFLL;

    /* max unsigned int value */
    static constexpr int MAX_UNSIGNED_SHORT_VALUE = 0xFFFF;

    /**
     * get unsigned int to int64_t
     *
     * @param bf byteBuffer
     * @return int64_t
     */
    static int64_t GetUnsignedInt(ByteBuffer& bf);

    /**
     * get unsigned short to int
     *
     * @param bf byteBuffer
     * @return int
     */
    static int GetUnsignedShort(ByteBuffer& bf);

    /**
     * set int64_t to unsigned int
     *
     * @param bf byteBuffer
     * @param value int64_t
     */
    static void SetUnsignedInt(ByteBuffer& bf, int64_t value);

    /**
     * set int to unsigned short
     *
     * @param bf byteBuffer
     * @param value int
     */
    static void SetUnsignedShort(ByteBuffer& bf, int value);

private:
    static constexpr int BIT_SIZE = 8;

    static constexpr int DOUBLE_BIT_SIZE = 16;

    static constexpr int TRIPLE_BIT_SIZE = 24;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_UNSIGNED_DECIMAL_UTIL_H