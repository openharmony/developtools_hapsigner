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

#ifndef SIGNERTOOLS_DATA_DESCRIPTOR_H
#define SIGNERTOOLS_DATA_DESCRIPTOR_H
#include "byte_buffer.h"
#include <vector>
namespace OHOS {
    namespace SignatureTools {
        class DataDescriptor {
            /**
             * DataDescriptor invariable bytes length
             */
        public:
            static constexpr int DES_LENGTH = 16;

            /**
             * 4 bytes , DataDescriptor signature
             */
            static constexpr int SIGNATURE = 0x08074b50;

            /**
             * 4 bytes
             */
        private:
            int crc32 = 0;

            /**
             * 4 bytes
             */
            uint64_t compressedSize = 0;

            /**
             * 4 bytes
             */
            uint64_t unCompressedSize = 0;

            /**
             * get Data Descriptor
             *
             * @param bytes DataDescriptor bytes
             * @return DataDescriptor
             * @throws ZipException read data descriptor exception
             */
        public:
            static DataDescriptor* GetDataDescriptor(std::vector<char>& bytes);

            /**
             * change DataDescriptor to bytes
             *
             * @return bytes
             */
            std::vector<char> ToBytes();

            static int GetDesLength();

            static int GetSIGNATURE();

            int GetCrc32();

            void SetCrc32(int crc32);

            uint64_t GetCompressedSize();

            void SetCompressedSize(uint64_t compressedSize);

            uint64_t GetUnCompressedSize();

            void SetUnCompressedSize(uint64_t unCompressedSize);
        };
    }
}
#endif
