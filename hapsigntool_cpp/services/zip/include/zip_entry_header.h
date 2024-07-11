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

#ifndef SIGNATRUETOOLS_ZIP_ENTRY_HEADER_H
#define SIGNATRUETOOLS_ZIP_ENTRY_HEADER_H

#include <string>

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
 */
class ZipEntryHeader {
public:
    /* ZipEntryHeader invariable bytes length */
    static constexpr int HEADER_LENGTH = 30;

    /* 4 bytes , entry header signature */
    static constexpr int SIGNATURE = 0x04034b50;

    /**
     * get Zip Entry Header
     *
     * @param bytes ZipEntryHeader bytes
     * @return ZipEntryHeader
     * @throws ZipException read entry header exception
     */
    static ZipEntryHeader* GetZipEntryHeader(const std::string& bytes);

    void ReadFileName(const std::string& bytes);

    void ReadExtra(const std::string& bytes);

    std::string ToBytes();

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

    int64_t GetCompressedSize();

    void SetCompressedSize(int64_t compressedSize);

    int64_t GetUnCompressedSize();

    void SetUnCompressedSize(int64_t unCompressedSize);

    int GetFileNameLength();

    void SetFileNameLength(int fileNameLength);

    int GetExtraLength();

    void SetExtraLength(int extraLength);

    std::string GetFileName() const;

    void SetFileName(const std::string& fileName);

    std::string GetExtraData() const;

    void SetExtraData(const std::string& extraData);

    int GetLength();

    void SetLength(int length);

private:
    /* 2 bytes */
    short m_version = 0;

    /* 2 bytes */
    short m_flag = 0;

    /* 2 bytes */
    short m_method = 0;

    /* 2 bytes */
    short m_lastTime = 0;

    /* 2 bytes */
    short m_lastDate = 0;

    /* 4 bytes */
    int m_crc32 = 0;

    /* 8 bytes */
    int64_t m_compressedSize = 0;

    /* 8 bytes */
    int64_t m_unCompressedSize = 0;

    /* 4 bytes */
    int m_fileNameLength = 0;

    /* 4 bytes */
    int m_extraLength = 0;

    /* n bytes */
    std::string m_fileName;

    /* n bytes */
    std::string m_extraData;

    int m_length = 0;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_ZIP_ENTRY_HEADER_H