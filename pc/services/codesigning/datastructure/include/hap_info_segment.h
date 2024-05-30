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
#ifndef SIGNATURETOOLS_HAP_INFO_SEGMENT_H
#define SIGNATURETOOLS_HAP_INFO_SEGMENT_H
#include <vector>
#include <string>
#include <cstdint>
#include "sign_info.h"
#include "byte_buffer.h"
#include "signature_tools_log.h"
namespace OHOS {
    namespace SignatureTools {
        class HapInfoSegment {
        private:
            static const int32_t MAGIC_NUM_BYTES;
            static const int32_t MAGIC_NUM;
            static const int32_t CHUNK_SIZE;
            int32_t magic;
            SignInfo signInfo;
        public:
            HapInfoSegment();
            HapInfoSegment(int32_t magic, SignInfo signInfo);
            void setSignInfo(SignInfo signInfo);
            SignInfo& getSignInfo();
            int32_t getSize();
            std::vector<int8_t> toByteArray();
            static HapInfoSegment fromByteArray(std::vector<int8_t> bytes);
        };
    }
}
#endif
