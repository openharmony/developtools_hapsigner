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
#ifndef SIGNERTOOLS_SIGH_HAP_H
#define SIGNERTOOLS_SIGH_HAP_H
#include "hap_utils.h"
#include "hap_verify_result.h"
#include "signer_config.h"
#include "signing_block_utils.h"
#include "securec.h"
#include <limits.h>
#include <unordered_map>
#include <vector>
#include <memory>

namespace OHOS {
    namespace SignatureTools {
        class SignHap {
            //class OptionalBlock;//类似如 SigningBlock java
        private:
            static constexpr int INT_SIZE = 4;
            static constexpr int CONTENT_VERSION = 2;
            static constexpr int BLOCK_NUMBER = 1;
            static constexpr int CONTENT_NUBER = 3;
            static constexpr int STORED_ENTRY_SO_ALIGNMENT = 4096;
            static constexpr int BUFFER_LENGTH = 4096;
            static constexpr int BLOCK_COUNT = 4;
            static constexpr int BLOCK_MAGIC = 16;
            static constexpr int BLOCK_VERSION = 4;
            static constexpr long INIT_OFFSET_LEN = 4L;
            static constexpr int OPTIONAL_TYPE_SIZE = 4;
            static constexpr int OPTIONAL_LENGTH_SIZE = 4;
            static constexpr int OPTIONAL_OFFSET_SIZE = 4;
        public:
            static bool Sign(DataSource* contents[], int32_t len, SignerConfig& config,
                std::vector<OptionalBlock>& optionalBlocks, ByteBuffer& result);
            static bool ComputeDigests(const DigestParameter& digestParam, DataSource* contents[], int32_t len,
                const std::vector<OptionalBlock>& optionalBlocks, ByteBuffer& result);
            static bool EncodeListOfPairsToByteArray(const DigestParameter& digestParam,
                const std::vector<std::pair<int32_t, ByteBuffer>>& contentDigests, ByteBuffer& result);
        private:
            static void ExtractedResult(std::vector<OptionalBlock>& optionalBlocks, ByteBuffer& result,
                std::unordered_map<int, int>& typeAndOffsetMap);
            static bool GenerateHapSigningBlock(std::vector<char>& hapSignatureSchemeBlock,
                std::vector<OptionalBlock>& optionalBlocks, int compatibleVersion, ByteBuffer& result);
        };
    }
}
#endif
