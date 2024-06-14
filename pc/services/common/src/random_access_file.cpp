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

#include <inttypes.h>

#include "securec.h"
#include "signature_info.h"
#include "signature_tools_log.h"
#include "verify_hap_openssl_utils.h"
#include "random_access_file.h"

namespace OHOS {
namespace SignatureTools {
int32_t RandomAccessFile::memoryPageSize = sysconf(_SC_PAGESIZE);

RandomAccessFile::RandomAccessFile()
    : fd(-1), fileLength(0)
{
}

RandomAccessFile::~RandomAccessFile()
{
    if (fd != -1) {
        close(fd);
    }
}

bool RandomAccessFile::Init(const std::string& filePath)
{
    fd = open(filePath.c_str(), O_RDWR);
    if (fd == -1) {
        PrintErrorNumberMsg("FILE OPEN FAIL", RET_FAILED, strerror(errno));
        return false;
    }

    if (memoryPageSize <= 0) {
        SIGNATURE_TOOLS_LOGE("getting pagesize failed. memoryPageSize: %{public}d", memoryPageSize);
        return false;
    }

    struct stat file_stat;
    if (fstat(fd, &file_stat) == -1) {
        SIGNATURE_TOOLS_LOGE("get file status failed");
        return false;
    }
    fileLength = file_stat.st_size;
    if (fileLength < 0) {
        SIGNATURE_TOOLS_LOGE("getting fileLength failed. fileLength: %{public}" PRId64, fileLength);
        return false;
    }

    return true;
}

int64_t RandomAccessFile::GetLength() const
{
    return fileLength;
}

bool RandomAccessFile::CheckLittleEndian()
{
    union LittleEndian {
        int32_t num;
        char ch;
    } t;
    t.num = 1;
    return (t.ch == 1);
}

int32_t RandomAccessFile::DoMMap(int32_t bufCapacity, int64_t offset, MmapInfo& mmapInfo)
{
    if (!CheckLittleEndian()) {
        SIGNATURE_TOOLS_LOGE("CheckLittleEndian: failed");
        return MMAP_FAILED;
    }

    // Starting address for memory mapping
    mmapInfo.mapAddr = reinterpret_cast<char*>(MAP_FAILED);
    if (fd == -1) {
        SIGNATURE_TOOLS_LOGE("FILE_OPEN_FAIL_ERROR_NUM");
        return FILE_IS_CLOSE;
    }
    if (offset < 0 || offset > fileLength - bufCapacity) {
        SIGNATURE_TOOLS_LOGE("offset is less than 0 OR offset is greater than fileLength - bufCapacity");
        return READ_OFFSET_OUT_OF_RANGE;
    }
    // Memory mapped file offset, 0 OR an integer multiple of 4K
    mmapInfo.mmapPosition = (offset / memoryPageSize) * memoryPageSize;
    // How many more bytes can be read from the current mapped memory page to find
    mmapInfo.readMoreLen = static_cast<int>(offset - mmapInfo.mmapPosition);
    mmapInfo.mmapSize = bufCapacity + mmapInfo.readMoreLen;
    mmapInfo.mapAddr = reinterpret_cast<char*>(mmap(nullptr,
                                               mmapInfo.mmapSize,
                                               // Specify protection requirements for the mapping area.
                                               // PROT_EXEC: The mapping area can be executed.
                                               // PROT_READ: The mapping area can be read.
                                               // PROT_WRITE: The mapping area can be written.
                                               // PROT_NONE: The mapping area is inaccessible.
                                               PROT_READ | PROT_WRITE,
                                               // Flag bit parameters.
                                               // MAP_SHARED: Modified memory data will be synchronized to a disk.
                                               // MAP_POPULATE: Prepare page tables in pre-read mode for file mapping.
                                               // Subsequent access to
                                               // the mapping area is not blocked by page violations.
                                               MAP_SHARED | MAP_POPULATE,
                                               // The file descriptor, the fd corresponding to the file to be mapped,
                                               // is obtained using open()
                                               fd,
                                               // The offset of the file map,
                                               // usually set to 0 to indicate
                                               // that the map starts at the head of the file,
                                               // must be an integer multiple of 4k or 0
                                               mmapInfo.mmapPosition));
    if (mmapInfo.mapAddr == MAP_FAILED) {
        SIGNATURE_TOOLS_LOGE("MAP_FAILED");
        return MMAP_FAILED;
    }
    return 0;
}

int32_t RandomAccessFile::ReadFileFullyFromOffset(char buf[], int64_t offset, int64_t bufCapacity)
{
    if (buf == nullptr) {
        SIGNATURE_TOOLS_LOGE("DEST_BUFFER_IS_NULL");
        return DEST_BUFFER_IS_NULL;
    }

    MmapInfo mmapInfo;
    int32_t ret = DoMMap(bufCapacity, offset, mmapInfo);
    if (ret < 0) {
        return ret;
    }

    if (memcpy_s(buf, bufCapacity, mmapInfo.mapAddr + mmapInfo.readMoreLen,
        mmapInfo.mmapSize - mmapInfo.readMoreLen) != EOK) {
        munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
        SIGNATURE_TOOLS_LOGE("MMAP_COPY_FAILED");

        return MMAP_COPY_FAILED;
    }
    munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
    return bufCapacity;
}

int32_t RandomAccessFile::ReadFileFullyFromOffset(ByteBuffer& buffer, int64_t offset)
{
    if (!buffer.HasRemaining()) {
        SIGNATURE_TOOLS_LOGE("DEST_BUFFER_IS_NULL");
        return DEST_BUFFER_IS_NULL;
    }

    MmapInfo mmapInfo;
    int32_t bufCapacity = buffer.GetCapacity();
    int64_t ret = DoMMap(bufCapacity, offset, mmapInfo);
    if (ret < 0) {
        return ret;
    }

    buffer.PutData(0, mmapInfo.mapAddr + mmapInfo.readMoreLen, bufCapacity);
    munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
    return bufCapacity;
}

int32_t RandomAccessFile::WriteToFile(ByteBuffer& buffer, int64_t position, int64_t length)
{
    // write file, file length may change
    int64_t remainLength = fileLength - position;
    fileLength = (length <= remainLength) ? fileLength : (fileLength + (length - remainLength));
    // update file length
    if (ftruncate(fd, fileLength) == -1) {
        perror("ftruncate");   // ftruncate: Invalid argument
        PrintErrorNumberMsg("ftruncate failed", RET_FAILED, strerror(errno));
        return -1;
    }

    int32_t bufCapacity = buffer.GetCapacity();
    if (bufCapacity == 0) {
        SIGNATURE_TOOLS_LOGE("DEST_BUFFER_IS_NULL");
        return DEST_BUFFER_IS_NULL;
    }

    MmapInfo mmapInfo;

    int64_t ret = DoMMap(bufCapacity, position, mmapInfo);
    if (ret < 0) {
        return ret;
    }

    memcpy_s(mmapInfo.mapAddr + mmapInfo.readMoreLen,
             mmapInfo.mmapSize - mmapInfo.readMoreLen,
             buffer.GetBufferPtr(), bufCapacity);
    munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
    return bufCapacity;
}

bool RandomAccessFile::ReadFileFromOffsetAndDigestUpdate(const DigestParameter& digestParam,
                                                         int32_t chunkSize, int64_t offset)
{
    MmapInfo mmapInfo;
    int32_t ret = DoMMap(chunkSize, offset, mmapInfo);
    if (ret < 0) {
        SIGNATURE_TOOLS_LOGE("DoMMap failed: %{public}d", ret);
        return false;
    }
    unsigned char* content = reinterpret_cast<unsigned char*>(mmapInfo.mapAddr + mmapInfo.readMoreLen);
    bool res = VerifyHapOpensslUtils::DigestUpdate(digestParam, content, chunkSize);
    munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
    return res;
}
}
}