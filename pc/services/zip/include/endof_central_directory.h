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

#ifndef SIGNERTOOLS_ENDOF_CENTRAL_DIRECTORY_H
#define SIGNERTOOLS_ENDOF_CENTRAL_DIRECTORY_H

#include <vector>
#include <optional>

namespace OHOS {
    namespace SignatureTools {
        class EndOfCentralDirectory {
            /**
             * EndOfCentralDirectory invariable bytes length
             */
        public:
            static constexpr int EOCD_LENGTH = 22;

            /**
             * 4 bytes , central directory signature
             */
            static constexpr int SIGNATURE = 0x06054b50;

            /**
             * 2 bytes
             */
        private:
            int diskNum = 0;

            /**
             * 2 bytes
             */
            int cDStartDiskNum = 0;

            /**
             * 2 bytes
             */
            int thisDiskCDNum = 0;

            /**
             * 2 bytes
             */
            int cDTotal = 0;

            /**
             * 4 bytes
             */
            uint64_t cDSize = 0;

            /**
             * 4 bytes
             */
            uint64_t offset = 0;

            /**
             * 2 bytes
             */
            int commentLength = 0;

            /**
             * n bytes
             */
            std::vector< char> comment;

            int length = 0;

            /**
             * init End Of Central Directory, default offset is 0
             *
             * @param bytes End Of Central Directory bytes
             * @return End Of Central Directory
             */
        public:
            static std::optional<EndOfCentralDirectory*> GetEOCDByBytes(std::vector< char>& bytes);

            /**
             * init End Of Central Directory
             *
             * @param bytes End Of Central Directory bytes
             * @param offset offset
             * @return End Of Central Directory
             */
            static std::optional<EndOfCentralDirectory*> GetEOCDByBytes(std::vector< char>& bytes, int offset);

            /**
             * change End Of Central Directory to bytes
             *
             * @return bytes
             */
            std::vector< char> ToBytes();

            static int GetEocdLength();

            static int GetSIGNATURE();

            int GetDiskNum();

            void SetDiskNum(int diskNum);

            int GetcDStartDiskNum();

            void SetcDStartDiskNum(int cDStartDiskNum);

            int GetThisDiskCDNum();

            void SetThisDiskCDNum(int thisDiskCDNum);

            int GetcDTotal();

            void SetcDTotal(int cDTotal);

            uint64_t GetcDSize();

            void SetcDSize(uint64_t cDSize);

            uint64_t GetOffset();

            void SetOffset(uint64_t offset);

            int GetCommentLength();

            void SetCommentLength(int commentLength);

            std::vector< char> GetComment();

            void SetComment(std::vector< char>& comment);

            int GetLength();

            void SetLength(int length);
        };
    }
}
#endif
