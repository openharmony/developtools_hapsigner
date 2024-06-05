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

#ifndef SIGNERTOOLS_HW_SIGN_HEAD_H
#define SIGNERTOOLS_HW_SIGN_HEAD_H
#include <string>
#include <vector>
namespace OHOS {
    namespace SignatureTools {
        class HwSignHead
        {
            public:
                HwSignHead();

            public:
                std::vector<int8_t> GetSignHead(int subBlockSize);

            public:
                /**
                 * length of sign head
                 */
                static const int SIGN_HEAD_LEN;

                /**
                 * sign hap magic string 16Bytes-Magic
                 */
                static const std::string MAGIC;

                /**
                 * sign elf magic string 16Bytes-Magic
                 */
                static const std::string ELF_MAGIC;

                /**
                 * sign block version 4-Bytes, version is 1.0.0.0
                 */
                static const std::string VERSION;
	
	            static const int32_t ELF_BLOCK_LEN;
	
                static const int32_t BIN_BLOCK_LEN;
	            static std::vector<int8_t> getSignHeadLittleEndian(int subBlockSize, int subBlockNum);
            private:
                static const int NUM_OF_BLOCK;
                static const int RESERVE_LENGTH;

            private:
                static std::vector<int8_t> reserve;
        };

    }
} // namespace OHOS

#endif