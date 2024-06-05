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
#ifndef SIGNATURETOOLS_SIGNED_FILE_POS_H
#define SIGNATURETOOLS_SIGNED_FILE_POS_H
#include <vector>
#include <string>
#include <memory>
#include <cstdint>
#include "byte_buffer.h"
namespace OHOS {
    namespace SignatureTools {
        class SignedFilePos {
        public:
            SignedFilePos(int32_t fileNameOffset,
                int32_t fileNameSize,
                int32_t signInfoOffset,
                int32_t signInfoSize);
        public:
            int32_t getFileNameOffset();
            int32_t getFileNameSize();
            int32_t getSignInfoOffset();
            int32_t getSignInfoSize();
            void increaseFileNameOffset(int32_t incOffset);
            void increaseSignInfoOffset(int32_t incOffset);
            static SignedFilePos fromByteArray(std::vector<int8_t> bytes);
        private:
            int32_t fileNameOffset;
            int32_t fileNameSize;
            int32_t signInfoOffset;
            int32_t signInfoSize;
        };
    }
}
#endif
