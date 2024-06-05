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
#ifndef SIGNATURETOOLS_CODE_SIGN_BLOCK_HEADER_H
#define SIGNATURETOOLS_CODE_SIGN_BLOCK_HEADER_H
#include <vector>
#include <string>
#include "byte_buffer.h"
#include "signature_tools_log.h"
namespace OHOS {
    namespace SignatureTools {
        class CodeSignBlockHeader {
        public:
            class Builder {
            public:
                long long magic = MAGIC_NUM;
                int version = CODE_SIGNING_VERSION;
                int blockSize = 0;
                int segmentNum = 0;
                int flags = 0;
                std::vector<signed char> reserved = std::vector<signed char>(RESERVED_BYTE_ARRAY_LENGTH);
            public:
                virtual Builder* setMagic(long long magic);
                virtual Builder* setVersion(int version);
                virtual Builder* setBlockSize(int blockSize);
                virtual Builder* setSegmentNum(int segmentNum);
                virtual Builder* setFlags(int flags);
                virtual Builder* setReserved(std::vector<signed char>& reserved);
                /**
             * Create a CodeSignBlockHeader object
             *
             * @return a CodeSignBlockHeader object
             */
                virtual CodeSignBlockHeader* build();
                virtual ~Builder();
            };
        public:
            static const int FLAG_MERKLE_TREE_INLINED = 0x1;
            static const int FLAG_NATIVE_LIB_INCLUDED = 0x2;
            // code signing version
        private:
            static const signed int  MAGIC_BYTE_LENGTH = 4;
            static constexpr int CODE_SIGNING_VERSION = 1;
            // byte size of magic number
            static const signed char MAGIC_BYTE_ARRAY_LENGTH = 8;
            // lower 8 bytes of MD5 result of string "hap code sign block" (E046 C8C6 5389 FCCD)
            static const long long MAGIC_NUM = ((0xE046C8C6LL << 32) + 0x5389FCCDLL);
            // size of byte[8] reserved
            static const signed char RESERVED_BYTE_ARRAY_LENGTH = 8;
            // At all times three segment are always included in code sign block
            // update this if new segments are created.
            static const int SEGMENT_NUM = 3;
            long long magic = 0;
            int version = 0;
            int blockSize = 0;
            int segmentNum = 0;
            // FLAG_MERKLE_TREE_INLINED + FLAG_NATIVE_LIB_INCLUDED
            int flags = 0;
            std::vector<signed char> reserved;
        public:
            CodeSignBlockHeader();
            CodeSignBlockHeader(Builder* builder);
            virtual ~CodeSignBlockHeader();
        public:
            virtual void setSegmentNum(int num);
            virtual int getSegmentNum();
            virtual void setBlockSize(long long size);
            virtual int getBlockSize();
            virtual void setFlags(int flags);
            virtual std::vector<int8_t> toByteArray();
            static CodeSignBlockHeader* fromByteArray(std::vector<signed char>& bytes);
            static int size();
            virtual std::string toString();
        };
    }
}
#endif
