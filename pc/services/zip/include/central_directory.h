/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef SIGNATRUETOOLS_CENTRAL_DIRECTORY_H
#define SIGNATRUETOOLS_CENTRAL_DIRECTORY_H

#include <string>

#include "byte_buffer.h"

namespace OHOS {
namespace SignatureTools {
class CentralDirectory {
public:
    // central directory invariable bytes length
    static constexpr int CD_LENGTH = 46;

    // 4 bytes, central directory signature
    static constexpr int SIGNATURE = 0x02014b50;

    static bool GetCentralDirectory(ByteBuffer& bf, CentralDirectory* cd);

    std::string ToBytes();

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

    int64_t GetCompressedSize();

    void SetCompressedSize(int64_t compressedSize);

    int64_t GetUnCompressedSize();

    void SetUnCompressedSize(int64_t unCompressedSize);

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

    int64_t GetOffset();

    void SetOffset(int64_t offset);

    std::string GetFileName();

    void SetFileName(const std::string& fileName);

    std::string GetExtraData() const;

    void SetExtraData(const std::string& extraData);

    std::string GetComment();

    void SetComment(const std::string& comment);

    int GetLength();

    void SetLength(int length);

private:
    /* 2 bytes */
    short version = 0;

    /* 2 bytes */
    short versionExtra = 0;

    /* 2 bytes */
    short flag = 0;

    /* 2 bytes */
    short method = 0;

    /* 2 bytes */
    short lastTime = 0;

    /* 2 bytes */
    short lastDate = 0;

    /* 4 bytes */
    int crc32 = 0;

    /* 8 bytes */
    int64_t compressedSize = 0;

    /* 8 bytes */
    int64_t unCompressedSize = 0;

    /* 4 bytes */
    int fileNameLength = 0;

    /* 4 bytes */
    int extraLength = 0;

    /* 4 bytes */
    int commentLength = 0;

    /* 4 bytes */
    int diskNumStart = 0;

    /* 2 bytes */
    short internalFile = 0;

    /* 4 bytes */
    int externalFile = 0;

    /* 8 bytes */
    int64_t offset = 0;

    /* n bytes */
    std::string fileName;

    /* n bytes */
    std::string extraData;

    /* n bytes */
    std::string comment;

    int length = 0;

    static void SetCentralDirectoryValues(ByteBuffer& bf, CentralDirectory* cd);
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_CENTRAL_DIRECTORY_H