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

#ifndef SIGNERTOOLS_SIGNATURE_BLOCK_TAGS_H
#define SIGNERTOOLS_SIGNATURE_BLOCK_TAGS_H

namespace OHOS {
namespace SignatureTools {
class SignatureBlockTags 
{
public:
    /**
     * Default value of signature block tags
     */
    static const char DEFAULT = 0;

    /**
     * The number of times get digest of whole package
     */
    static const char HASH_ALL = 1;

    /**
     * Ii is root node tag of Merkle tree.
     * This tag mean the digest of Merkle tree and the data size of each tree node is 1M bytes.
     */
    static const char HASH_ROOT_1M = 0x80;

    /**
     * Ii is root node tag of Merkle tree.
     * This tag mean the digest of Merkle tree and the data size of each tree node is 512K bytes.
     */
    static const char HASH_ROOT_512K = 0x81;

    /**
     * Ii is root node tag of Merkle tree.
     * This tag mean the digest of Merkle tree and the data size of each tree node is 256K bytes.
     */
    static const char HASH_ROOT_256K = 0x82;

    /**
     * Ii is root node tag of Merkle tree.
     * This tag mean the digest of Merkle tree and the data size of each tree node is 128K bytes.
     */
    static const char HASH_ROOT_128K = 0x83;

    /**
     * Ii is root node tag of Merkle tree.
     * This tag mean the digest of Merkle tree and the data size of each tree node is 64K bytes.
     */
    static const char HASH_ROOT_64K = 0x84;

    /**
     * Ii is root node tag of Merkle tree.
     * This tag mean the digest of Merkle tree and the data size of each tree node is 32K bytes.
     */
    static const char HASH_ROOT_32K = 0x85;

    /**
     * Ii is root node tag of Merkle tree.
     * This tag mean the digest of Merkle tree and the data size of each tree node is 16K bytes.
     */
    static const char HASH_ROOT_16K = 0x86;

    /**
     * Ii is root node tag of Merkle tree.
     * This tag mean the digest of Merkle tree and the data size of each tree node is 8K bytes.
     */
    static const char HASH_ROOT_8K = 0x87;

    /**
     * Ii is root node tag of Merkle tree.
     * This tag mean the digest of Merkle tree and the data size of each tree node is 4K bytes.
     */
    static const char HASH_ROOT_4K = 0x88;

    /**
     * The digest of block is 1M bytes.
     */
    static const char HASH_BLOCK_1M = 0x90;

    /**
     * The digest of block is 512K bytes.
     */
    static const char HASH_BLOCK_512K = 0x91;

    /**
     * The digest of block is 256k bytes.
     */
    static const char HASH_BLOCK_256K = 0x92;

    /**
     * The digest of block is 128k bytes.
     */
    static const char HASH_BLOCK_128K = 0x93;

    /**
     * The digest of block is 64k bytes.
     */
    static const char HASH_BLOCK_64K = 0x94;

    /**
     * The digest of block is 32k bytes.
     */
    static const char HASH_BLOCK_32K = 0x95;

    /**
     * The digest of block is 16k bytes.
     */
    static const char HASH_BLOCK_16K = 0x96;

    /**
     * The digest of block is 8k bytes.
     */
    static const char HASH_BLOCK_8K = 0x97;

    /**
     * The digest of block is 4k bytes.
     */
    static const char HASH_BLOCK_4K = 0x98;
};

}
} // namespace OHOS

#endif