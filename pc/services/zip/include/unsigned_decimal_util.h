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

#ifndef SIGNERTOOLS_UNSIGNED_DECIMAL_UTIL_H
#define SIGNERTOOLS_UNSIGNED_DECIMAL_UTIL_H

#include "byte_buffer.h"

namespace OHOS {
    namespace SignatureTools {
        class UnsignedDecimalUtil {
            /**
             * max unsigned int value
             */
        public:
            static constexpr long long MAX_UNSIGNED_INT_VALUE = 0xFFFFFFFFLL;

            /**
             * max unsigned int value
             */
            static constexpr int MAX_UNSIGNED_SHORT_VALUE = 0xFFFF;

        private:
            static constexpr int BIT_SIZE = 8;

            static constexpr int DOUBLE_BIT_SIZE = 16;

            static constexpr int TRIPLE_BIT_SIZE = 24;

            /**
             * get unsigned int to long
             *
             * @param bf byteBuffer
             * @return long
             */
        public:
            static long long GetUnsignedInt(ByteBuffer& bf);

            /**
             * get unsigned short to int
             *
             * @param bf byteBuffer
             * @return int
             */
            static int GetUnsignedShort(ByteBuffer& bf);

            /**
             * set long to unsigned int
             *
             * @param bf byteBuffer
             * @param value long
             */
            static void SetUnsignedInt(ByteBuffer& bf, long long value);

            /**
             * set int to unsigned short
             *
             * @param bf byteBuffer
             * @param value int
             */
            static void SetUnsignedShort(ByteBuffer& bf, int value);
        };
    }
}
#endif
