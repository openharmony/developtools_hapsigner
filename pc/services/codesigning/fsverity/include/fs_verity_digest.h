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
#ifndef SIGNATURETOOLS_FSVERITY_DIGEST_H
#define SIGNATURETOOLS_FSVERITY_DIGEST_H
#include "byte_buffer.h"
#include <string>
#include <vector>
#include <memory>
namespace OHOS {
    namespace SignatureTools {
        /**
         * Format of FsVerity digest
         * int8[8] magic              "FSVerity"
         * le16    digestAlgorithm    sha256 = 1, sha512 = 2
         * le16    digestSize
         * uint8[] digest
         **/
        class FsVerityDigest {
        private:
            static const std::string FSVERITY_DIGEST_MAGIC;
            static const int DIGEST_HEADER_SIZE;
        public:
            /**
             * Get formatted FsVerity digest
             *
             * @param algoID hash algorithm id
             * @param digest raw digest computed from input
             * @return formatted FsVerity digest bytes
             */
            static std::vector<int8_t> GetFsVerityDigest(int8_t algoID, std::vector<int8_t>& digest);
        };
    } // namespace SignatureTools
} // namespace OHOS
#endif