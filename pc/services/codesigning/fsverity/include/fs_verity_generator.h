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
#ifndef SIGNATURETOOLS_FSVERITY_GENERATOR_H
#define SIGNATURETOOLS_FSVERITY_GENERATOR_H
#include "merkle_tree.h"
#include "merkle_tree_builder.h"
#include "fs_verity_descriptor.h"
#include "fs_verity_digest.h"
#include <vector>
#include <istream>
#include <memory>
namespace OHOS {
    namespace SignatureTools {
        // FsVerity data generator supper class
        class FsVerityGenerator {
        private:
            /**
            * FsVerity hash algorithm
            */
            static const FsVerityHashAlgorithm FS_VERITY_HASH_ALGORITHM;
            static const int8_t LOG_2_OF_FSVERITY_HASH_PAGE_SIZE;
        protected:
            /**
             * salt for hashing one page
             */
            std::vector<int8_t> salt;
        private:
            std::vector<int8_t> fsVerityDigest;
            std::vector<int8_t> treeBytes;
            std::vector<int8_t> rootHash;
        public:
            /**
             * generate merkle tree of given input
             *
             * @param inputStream           input stream for generate merkle tree
             * @param size                  total size of input stream
             * @param fsVerityHashAlgorithm hash algorithm for FsVerity
             * @return merkle tree
             * @throws FsVerityDigestException if error
             */
            MerkleTree* GenerateMerkleTree(std::istream& inputStream, long size,
                const FsVerityHashAlgorithm& fsVerityHashAlgorithm);
            /**
         * generate FsVerity digest of given input
         *
         * @param inputStream   input stream for generate FsVerity digest
         * @param size          total size of input stream
         * @param fsvTreeOffset merkle tree raw bytes offset based on the start of file
         * @throws FsVerityDigestException if error
         */
            void GenerateFsVerityDigest(std::istream& inputStream, long size, long fsvTreeOffset);
            /**
         * Get FsVerity digest
         *
         * @return bytes of FsVerity digest
         */
            std::vector<int8_t> GetFsVerityDigest()
            {
                return fsVerityDigest;
            }

            std::vector<int8_t> Getsalt()
            {
                return salt;
            }
            /**
         * Get merkle tree in bytes
         *
         * @return bytes of merkle tree
         */
            std::vector<int8_t> GetTreeBytes()
            {
                return treeBytes;
            }
            /**
         * Get merkle tree rootHash in bytes
         *
         * @return bytes of merkle tree rootHash
         */
            std::vector<int8_t> GetRootHash()
            {
                return rootHash;
            }
            std::vector<int8_t> GetSalt()
            {
                return salt;
            }
            /**
         * Returns byte size of salt
         *
         * @return byte size of salt
         */
            int GetSaltSize()
            {
                return (this->salt).empty() ? 0 : (this->salt).size();
            }
            /**
         * Returns the id of fs-verity hash algorithm
         *
         * @return fs-verity hash algorithm id
         */
            static uint8_t GetFsVerityHashAlgorithm()
            {
                return FS_VERITY_HASH_ALGORITHM.GetId();
            }
            /**
         * Returns the log2 of size of data and tree blocks
         *
         * @return log2 of size of data and tree blocks
         */
            static uint8_t GetLog2BlockSize()
            {
                return LOG_2_OF_FSVERITY_HASH_PAGE_SIZE;
            }
        };
    } // namespace SignatureTools
} // namespace OHOS
#endif