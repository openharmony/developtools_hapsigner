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
#ifndef SIGNATURETOOLS_MERKLE_TREE_BUILDER_H
#define SIGNATURETOOLS_MERKLE_TREE_BUILDER_H
#include <algorithm>
#include <string>
#include <vector>
#include <iostream>
#include <memory>
#include <sstream>
#include "thread_pool.h"
#include "byte_buffer.h"
#include "merkle_tree.h"
#include "fs_digest_utils.h"
namespace OHOS {
    namespace SignatureTools {
        class MerkleTreeBuilder {
        private:
            static const int FSVERITY_HASH_PAGE_SIZE;
            static const long long INPUTSTREAM_MAX_SIZE;
            static const int CHUNK_SIZE;
            static const long MAX_READ_SIZE;
            static const int MAX_PROCESSORS;
            static const int BLOCKINGQUEUE;
            const int POOL_SIZE = std::min(MAX_PROCESSORS, static_cast<int>(std::thread::hardware_concurrency()));
            std::string mAlgorithm = "SHA-256";
            /*
        private final ExecutorService mPools = new ThreadPoolExecutor(POOL_SIZE, POOL_SIZE, 0L, TimeUnit.MILLISECONDS,
        new ArrayBlockingQueue<>(BLOCKINGQUEUE), new ThreadPoolExecutor.CallerRunsPolicy());
        */

            std::shared_ptr<Uscript::ThreadPool> mPools;
        public:
            MerkleTreeBuilder();
            /**
            * generate merkle tree of given input
            *
            * @param inputStream           input stream for generate merkle tree
            * @param size                  total size of input stream
            * @param fsVerityHashAlgorithm hash algorithm for FsVerity
            * @return merkle tree
            * @throws IOException              if error
            * @throws NoSuchAlgorithmException if error
            */
            MerkleTree* GenerateMerkleTree(std::istream& inputStream, long size,
                const FsVerityHashAlgorithm& fsVerityHashAlgorithm);
        private:
            /**
            * set algorithm
            *
            * @param algorithm hash algorithm
            */
            void SetAlgorithm(const std::string& algorithm);
            /**
        * translation inputStream to hash data
        *
        * @param inputStream  input stream for generating merkle tree
        * @param size         total size of input stream
        * @param outputBuffer hash data
        * @throws IOException if error
        */
            void TransInputStreamToHashData(std::istream& inputStream, long size,
                ByteBuffer* outputBuffer, int bufStartIdx);
            /**
        * split buffer by begin and end information
        *
        * @param buffer original buffer
        * @param begin  begin position
        * @param end    end position
        * @return slice buffer
        */
            static ByteBuffer* Slice(ByteBuffer* buffer, int begin, int end);
            /**
        * calculate merkle tree level and size by data size and digest size
        *
        * @param dataSize   original data size
        * @param digestSize algorithm data size
        * @return level offset list, contains the offset of
        * each level from the root node to the leaf node
        */
            static std::vector<int64_t> GetOffsetArrays(long dataSize, int digestSize);
            /**
        * calculate data size list by data size and digest size
        *
        * @param dataSize   original data size
        * @param digestSize algorithm data size
        * @return data size list, contains the offset of
        * each level from the root node to the leaf node
        */
            static std::vector<long> GetLevelSize(long dataSize, int digestSize);
            void RunHashTask(std::vector<std::vector<int8_t>>& hashes, ByteBuffer* buffer,
                int readChunkIndex, int bufStartIdx);
            /**
        * hash data of buffer
        *
        * @param inputBuffer  original data
        * @param outputBuffer hash data
        */
            void TransInputDataToHashData(ByteBuffer* inputBuffer, ByteBuffer* outputBuffer,
                int64_t bufStartIdx, int64_t outputStartIdx);
            /**
         * translation inputBuffer arrays to hash ByteBuffer
         *
         * @param inputStream  input stream for generate merkle tree
         * @param size         total size of input stream
         * @param outputBuffer hash data
         * @param offsetArrays level offset
         * @param digestSize   algorithm output byte size
         * @throws IOException if error
         */
            void GenerateHashDataByInputData(std::istream& inputStream, long size, ByteBuffer* outputBuffer,
                std::vector<int64_t>& offsetArrays, int digestSize);
            /**
        * get buffer data by level offset, transforms digest data, save in another
        * memory
        *
        * @param buffer       hash data
        * @param offsetArrays level offset
        * @param digestSize   algorithm output byte size
        */
            void GenerateHashDataByHashData(ByteBuffer* buffer, std::vector<int64_t>& offsetArrays, int digestSize);
            /**
        * generate merkle tree of given input
        *
        * @param dataBuffer            tree data memory block
        * @param inputDataSize         total size of input stream
        * @param fsVerityHashAlgorithm hash algorithm for FsVerity
        * @return merkle tree
        * @throws NoSuchAlgorithmException if error
        */
            MerkleTree* GetMerkleTree(ByteBuffer* dataBuffer, long inputDataSize,
                FsVerityHashAlgorithm fsVerityHashAlgorithm);
            /**
        * generate merkle tree of given input
        *
        * @param data             original data
        * @param originalDataSize data size
        * @param digestSize       algorithm output byte size
        */
            void DataRoundupChunkSize(ByteBuffer* data, long originalDataSize, int digestSize);
            /**
        * get mount of chunks to store data
        *
        * @param dataSize   data size
        * @param divisor    split chunk size
        * @return chunk count
        */
            static long GetChunkCount(long dataSize, long divisor);
            /**
        * get total size of chunk to store data
        *
        * @param dataSize   data size
        * @param divisor    split chunk size
        * @param multiplier chunk multiplier
        * @return chunk size
        */
            static long GetFullChunkSize(long dataSize, long divisor, long multiplier);
        };
    } // namespace SignatureTools
} // namespace OHOS
#endif