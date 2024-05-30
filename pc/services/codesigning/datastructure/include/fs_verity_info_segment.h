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
#ifndef SIGNATURETOOLS_FS_VERITY_INFO_SEGMENT_H
#define SIGNATURETOOLS_FS_VERITY_INFO_SEGMENT_H
#include <vector>
#include <string>
#include "signature_tools_log.h"
#include "fs_verity_descriptor.h"
#include "fs_verity_generator.h"
namespace OHOS {
    namespace SignatureTools {
        class FsVerityInfoSegment {
            /**
             * fs-verity info segment size in bytes
             */
        public:
            static constexpr int FS_VERITY_INFO_SEGMENT_SIZE = 64;
            // lower 4 bytes of the MD5 result of string "fs-verity info segment" (1E38 31AB)
        private:
            static const int MAGIC;
            static const int RESERVED_BYTE_ARRAY_LENGTH;
            int magic = MAGIC;
            signed char hashAlgorithm = 0;
            signed char version = 0;
            signed char log2BlockSize = 0;
            std::vector<int8_t> reserved;
        public:
            FsVerityInfoSegment();
            FsVerityInfoSegment(signed char version, signed char hashAlgorithm, signed char log2BlockSize);
            FsVerityInfoSegment(int magic, signed char version, signed char hashAlgorithm,
                                signed char log2BlockSize, std::vector<int8_t> reserved);
            virtual ~FsVerityInfoSegment();
            virtual int size();
            virtual std::vector<int8_t> toByteArray();
            static FsVerityInfoSegment fromByteArray(std::vector<int8_t> bytes);
            virtual std::string toString();
        };
    }
}
#endif
