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

#ifndef SIGNERTOOLS_CENTRAL_DIRECTORY_H
#define SIGNERTOOLS_CENTRAL_DIRECTORY_H

#include <string>
#include <vector>
#include "byte_buffer.h"

namespace OHOS {
    namespace SignatureTools {
        class CentralDirectory {
            /**
             * central directory invariable bytes length
             */
        public:
            static constexpr int CD_LENGTH = 46;

            /**
             * 4 bytes , central directory signature
             */
            static constexpr int SIGNATURE = 0x02014b50;

            /**
             * 2 bytes
             */
        private:
            short version = 0;

            /**
             * 2 bytes
             */
            short versionExtra = 0;

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
             * 2 bytes
             */
            int commentLength = 0;

            /**
             * 2 bytes
             */
            int diskNumStart = 0;

            /**
             * 2 bytes
             */
            short internalFile = 0;

            /**
             * 4 bytes
             */
            int externalFile = 0;

            /**
             * 4 bytes
             */
            long long offset = 0;

            /**
             * n bytes
             */
            std::string fileName;

            /**
             * n bytes
             */
            std::vector<char> extraData;

            /**
             * n bytes
             */
            std::vector<char> comment;

            int length = 0;

            /**
             * get Central Directory
             *
             * @param bf ByteBuffer
             * @return CentralDirectory
             * @throws ZipException read Central Directory exception
             */
        public:
            static bool GetCentralDirectory(ByteBuffer& bf, CentralDirectory* cd);

            /**
             * change Central Directory to bytes
             *
             * @return bytes
             */
            std::vector<char> ToBytes();

            static int GetCdLength();

            static int GetSIGNATURE();

            short GetVersion();

            void SetVersion(short version);

            short GetVersionExtra();

            void SetVersionExtra(short versionExtra);

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

            int GetCommentLength();

            void SetCommentLength(int commentLength);

            int GetDiskNumStart();

            void SetDiskNumStart(int diskNumStart);

            short GetInternalFile();

            void SetInternalFile(short internalFile);

            int GetExternalFile();

            void SetExternalFile(int externalFile);

            long long GetOffset();

            void SetOffset(long long offset);

            std::string GetFileName();

            void SetFileName(const std::string& fileName);

            std::vector<char> GetExtraData();

            void SetExtraData(std::vector<char>& extraData);

            std::vector<char> GetComment();

            void SetComment(std::vector<char>& comment);

            int GetLength();

            void SetLength(int length);

        private:
            static void SetCentralDirectoryValues(ByteBuffer& bf, CentralDirectory* cd);
        };
    }
}
#endif
