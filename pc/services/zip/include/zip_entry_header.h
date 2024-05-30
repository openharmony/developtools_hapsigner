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

#ifndef SIGNERTOOLS_ZIPENTRYHEADER_H
#define SIGNERTOOLS_ZIPENTRYHEADER_H

#include <string>
#include <vector>
#include "byte_buffer.h"

namespace OHOS {
    namespace SignatureTools {
        /**
         * resolve zip ZipEntryHeader data
         * end of central dir signature    4 bytes  (0x06054b50)
         * number of this disk             2 bytes
         * number of the disk with the
         * start of the central directory  2 bytes
         * total number of entries in the
         * central directory on this disk  2 bytes
         * total number of entries in
         * the central directory           2 bytes
         * size of the central directory   4 bytes
         * offset of start of central
         * directory with respect to
         * the starting disk number        4 bytes
         * .ZIP file comment length        2 bytes
         * .ZIP file comment       (variable size)
         *
         * @since 2023/12/02
         */
        class ZipEntryHeader {
            /**
             * ZipEntryHeader invariable bytes length
             */
        public:
            static constexpr int HEADER_LENGTH = 30;

            /**
             * 4 bytes , entry header signature
             */
            static constexpr int SIGNATURE = 0x04034b50;

            /**
             * 2 bytes
             */
        private:
            short version = 0;

            /**
             * 2 bytes
             */
            short flag = 0;

            /**
             * 2 bytes
             */
            short method = 0;

            /**
             * 2 bytes
             */
            short lastTime = 0;

            /**
             * 2 bytes
             */
            short lastDate = 0;

            /**
             * 4 bytes
             */
            int crc32 = 0;

            /**
             * 4 bytes
             */
            long long compressedSize = 0;

            /**
             * 4 bytes
             */
            long long unCompressedSize = 0;

            /**
             * 2 bytes
             */
            int fileNameLength = 0;

            /**
             * 2 bytes
             */
            int extraLength = 0;

            /**
             * n bytes
             */
            std::string fileName;

            /**
             * n bytes
             */
            std::vector< char> extraData;

            int length = 0;

            /**
             * get Zip Entry Header
             *
             * @param bytes ZipEntryHeader bytes
             * @return ZipEntryHeader
             * @throws ZipException read entry header exception
             */
        public:
            static ZipEntryHeader* GetZipEntryHeader(std::vector<char>& bytes);

            /**
             * set entry header name
             *
             * @param bytes name bytes
             */
            void ReadFileName(std::vector<char>& bytes);

            /**
             * set entry header  extra
             *
             * @param bytes extra bytes
             */
            void ReadExtra(std::vector<char>& bytes);

            /**
             * change Zip Entry Header to bytes
             *
             * @return bytes
             */
            std::vector< char> ToBytes();

            static int GetHeaderLength();

            static int GetSIGNATURE();

            short GetVersion();

            void SetVersion(short version);

            short GetFlag();

            void SetFlag(short flag);

            short GetMethod();

            void SetMethod(short method);

            short GetLastTime();

            void SetLastTime(short lastTime);

            short GetLastDate();

            void SetLastDate(short lastDate);

            int GetCrc32();

            void SetCrc32(int crc32);

            long long GetCompressedSize();

            void SetCompressedSize(long long compressedSize);

            long long GetUnCompressedSize();

            void SetUnCompressedSize(long long unCompressedSize);

            int GetFileNameLength();

            void SetFileNameLength(int fileNameLength);

            int GetExtraLength();

            void SetExtraLength(int extraLength);

            std::string GetFileName();

            void SetFileName(const std::string& fileName);

            std::vector<char> GetExtraData();

            void SetExtraData(std::vector<char>& extraData);

            int GetLength();

            void SetLength(int length);
        };
    }
}
#endif
