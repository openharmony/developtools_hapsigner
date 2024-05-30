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
#ifndef SIGNATURETOOLS_HAP_UTILS_H
#define SIGNATURETOOLS_HAP_UTILS_H

#include <set>
#include <vector>
#include <string>
#include <unordered_map>
#include <utility>
#include <memory>
#include "content_digest_algorithm.h"
#include "signing_block.h"
#include "hash.h"
#include "zip_data_input.h"
#include "signature_tools_log.h"

namespace OHOS {
    namespace SignatureTools {
        class HapUtils {
            /**
             * Hap sign block info
             */
        public:
            class HapSignBlockInfo {
            private:
                const long long offset;
                const int version;
                ByteBuffer const content;

            public:
                virtual ~HapSignBlockInfo()
                {
                }

                HapSignBlockInfo(long long offset, int version, ByteBuffer contentByteBuffer);

                virtual int getVersion();

                virtual ByteBuffer getContent();

                virtual long long getOffset();
            };

        private:
            //static const Logger* LOGGER;

            /**
             * ID of hap signature blocks of version 1
             */
        public:
            static constexpr int HAP_SIGNATURE_SCHEME_V1_BLOCK_ID = 0x20000000;

            /**
             * ID of hap proof of rotation block
             */
            static constexpr int HAP_PROOF_OF_ROTATION_BLOCK_ID = 0x20000001;

            /**
             * ID of profile block  = 536870914 profile签名块
             */
            static constexpr int HAP_PROFILE_BLOCK_ID = 0x20000002;

            /**
             * ID of property block = 536870915 代码签名块
             */
            static constexpr int HAP_PROPERTY_BLOCK_ID = 0x20000003;

            /**
             * ID of property block
             */
            static constexpr int HAP_CODE_SIGN_BLOCK_ID = 0x30000001;

            /**
             * The size of data block used to get digest
             */

            static constexpr int CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES = 1024 * 1024;

            /**
             * Content version
             */
            static constexpr int CONTENT_VERSION = 2;

            /**
             * bit size
             */
            static constexpr int BIT_SIZE = 8;

            /**
             * half bit size
             */
            static constexpr int HALF_BIT_SIZE = 4;

            /**
             * int size
             */
            static constexpr int INT_SIZE = 4;

            /**
             * block number
             */
            static constexpr int BLOCK_NUMBER = 1;

            /**
             * hap sign schema v2 signature block version
             */
            static constexpr int HAP_SIGN_SCHEME_V2_BLOCK_VERSION = 2;

            /**
             * hap sign schema v3 signature block version
             */
            static constexpr int HAP_SIGN_SCHEME_V3_BLOCK_VERSION = 3;

            /**
             * The value of lower 8-bytes of old magic word
             */
            static constexpr long long HAP_SIG_BLOCK_MAGIC_LO_V2 = 0x2067695320504148LL;

            /**
             * The value of higher 8-bytes of old magic word
             */
            static constexpr long long HAP_SIG_BLOCK_MAGIC_HI_V2 = 0x3234206b636f6c42LL;

            /**
             * The value of lower 8 bytes of magic word
             */
            static constexpr long long HAP_SIG_BLOCK_MAGIC_LO_V3 = 0x676973207061683cLL;

            /**
             * The value of higher 8 bytes of magic word
             */
            static constexpr long long HAP_SIG_BLOCK_MAGIC_HI_V3 = 0x3e6b636f6c62206eLL;

            /**
             * Size of hap signature block header
             */
            static constexpr int HAP_SIG_BLOCK_HEADER_SIZE = 32;

            /**
             * The min size of hap signature block
             */
            static constexpr int HAP_SIG_BLOCK_MIN_SIZE = HAP_SIG_BLOCK_HEADER_SIZE;

            /**
             * hap block size
             */
            static constexpr int BLOCK_SIZE = 8;

            /**
             * The set of IDs of optional blocks in hap signature block.
             */
        private:
            static const int32_t MAX_APP_ID_LEN = 32;
            static const std::string HAP_DEBUG_OWNER_ID;
            static std::set<int> HAP_SIGNATURE_OPTIONAL_BLOCK_IDS;

            /**
             * Minimum api version for hap sign schema v3.
             */
            static constexpr int MIN_COMPATIBLE_VERSION_FOR_SCHEMA_V3 = 8;

            /**
             * Magic word of hap signature block v2
             */
            static const std::vector<signed char> HAP_SIGNING_BLOCK_MAGIC_V2;

            /**
             * Magic word of hap signature block
             */
            static const std::vector<signed char> HAP_SIGNING_BLOCK_MAGIC_V3;

            static constexpr signed char ZIP_FIRST_LEVEL_CHUNK_PREFIX = 0x5a;
            static const signed char ZIP_SECOND_LEVEL_CHUNK_PREFIX = static_cast<signed char>(0xa5);
            static const int DIGEST_PRIFIX_LENGTH = 5;
            static constexpr int BUFFER_LENGTH = 4096;
            static const std::string HEX_CHAR_ARRAY;

            /**
             * The set of IDs of optional blocks in hap signature block.
             */
        private:
            class StaticConstructor {
            public:
                StaticConstructor();
            };

        private:
            static HapUtils::StaticConstructor staticConstructor;

            HapUtils();

            /**
             * Get HAP_SIGNATURE_OPTIONAL_BLOCK_IDS
             *
             * @return HAP_SIGNATURE_OPTIONAL_BLOCK_IDS
             */
        public:
            static std::string getAppIdentifier(const std::string& profileContent);

            static std::pair<std::string, std::string> parseAppIdentifier(const std::string& profileContent);

            static std::set<int> GetHapSignatureOptionalBlockIds();

            /**
             * Get HAP_SIGNING_BLOCK_MAGIC
             *
             * @param compatibleVersion compatible api version
             * @return HAP_SIGNING_BLOCK_MAGIC
             */
            static std::vector<signed char> GetHapSigningBlockMagic(int compatibleVersion);

            /**
             * Get version number of hap signature block
             *
             * @param compatibleVersion compatible api version
             * @return magic to number
             */
            static int GetHapSigningBlockVersion(int compatibleVersion);

            /**
             * Read data from hap file.
             *
             * @param file input file path.
             * @return true, if read successfully.
             * @throws IOException on error.
             */
            static bool ReadFileToByteBuffer(const std::string& file, ByteBuffer& buffer);
        };
    }
}
#endif
