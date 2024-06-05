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
#ifndef SIGNATURETOOLS_NATIVE_LIB_INFO_SEGMENT_H
#define SIGNATURETOOLS_NATIVE_LIB_INFO_SEGMENT_H
#include <vector>
#include <string>
#include "sign_info.h"
#include "signed_file_pos.h"
#include "signature_tools_log.h"
namespace OHOS {
    namespace SignatureTools {
        class NativeLibInfoSegment {
        public:
            NativeLibInfoSegment();
            void setSoInfoList(std::vector<std::pair<std::string, SignInfo>> soInfoList);
            int32_t getSectionNum();
            std::vector<std::string> getFileNameList();
            std::vector<SignInfo> getSignInfoList();
            int32_t size();
            std::vector<int8_t> toByteArray();
            static NativeLibInfoSegment fromByteArray(std::vector<int8_t> bytes);
        public:
            NativeLibInfoSegment(int32_t magic,
                int32_t segmentSize,
                int32_t sectionNum,
                std::vector<SignedFilePos> signedFilePosList,
                std::vector<std::string> fileNameList,
                std::vector<SignInfo> signInfoList,
                std::vector<int8_t> zeroPadding
            );
            static const int32_t MAGIC_LENGTH_SECNUM_BYTES = 12;
            static const int32_t SIGNED_FILE_POS_SIZE = 16;
            static const int32_t MAGIC_NUM = (0x0ED2 << 16) + 0xE720;
            static const int32_t ALIGNMENT_FOR_SIGNINFO = 4;
        private:
            int32_t magic;
            int32_t segmentSize;
            int32_t sectionNum;
            std::vector<std::pair<std::string, SignInfo>> soInfoList;
            std::vector<SignedFilePos> signedFilePosList;
            std::vector<std::string> fileNameList;
            std::vector<SignInfo> signInfoList;
            std::vector<int8_t> zeroPadding;
            int32_t fileNameListBlockSize;
            int32_t signInfoListBlockSize;
            void generateList();
        };
    }
}
#endif
