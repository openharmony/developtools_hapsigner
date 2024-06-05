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

#ifndef SIGNERTOOLS_HW_BLOCK_HEAD_H
#define SIGNERTOOLS_HW_BLOCK_HEAD_H

#include <vector>
#include <string>

namespace OHOS {
namespace SignatureTools {
class HwBlockHead {
public:
    /**
     * bin file sign block length is 8 byte
     */
    static const int BLOCK_LEN = 8;

    /**
     * elf file sign block length is 12 byte
     */
    static const int ELF_BLOCK_LEN = 12;

    static const int BIT_SIZE = 8;
    static const int DOUBLE_BIT_SIZE = 16;
    static const int TRIPLE_BIT_SIZE = 24;
    static const int32_t SIGN_HEAD_LEN = 32;
public:
    static int GetBlockLen();

    /**
     * get elf block length
     *
     * @return return elf block length
     */
    static int GetElfBlockLen();

    /**
     * get serialization of file type bin BlockHead
     *
     * @param type type of signature block
     * @param tag tags of signature block
     * @param length the length of block data
     * @param offset Byte offset of the data block relative to the start position of the signature block
     * @return Byte array after serialization of HwBlockHead
     */
    static std::string GetBlockHead(char type, char tag, short length, int offset);

    /**
     * get serialization of file type elf BlockHead
     *
     * @param type type of signature block
     * @param tag tags of signature block
     * @param length the length of block data
     * @param offset Byte offset of the data block relative to the start position of the signature block
     * @return Byte array after serialization of HwBlockHead
     */
    static std::string GetBlockHeadLittleEndian(char type, char tag, int length, int offset);
	static std::vector<int8_t> getBlockHeadLittleEndian(char type, char tag, int length, int offset);
};
} // namespace SignatureTools
} // namespace OHOS
#endif