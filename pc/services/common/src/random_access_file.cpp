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
#include "random_access_file.h"
#include <cerrno>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "signature_info.h"
#include "signature_tools_log.h"
#include "securec.h"
#include "verify_openssl_utils.h"
namespace OHOS {
    namespace SignatureTools {
        const int32_t RandomAccessFile::FILE_OPEN_FAIL_ERROR_NUM = -1;
        int32_t RandomAccessFile::memoryPageSize = sysconf(_SC_PAGESIZE);
        RandomAccessFile::RandomAccessFile()
            : fd(FILE_OPEN_FAIL_ERROR_NUM), fileLength(0)
        {
        }
        RandomAccessFile::~RandomAccessFile()
        {
            if (fd != FILE_OPEN_FAIL_ERROR_NUM) {
                close(fd);
            }
        }
        bool RandomAccessFile::Init(const std::string& filePath)
        {
            fd = open(filePath.c_str(), O_RDWR);
            if (fd == FILE_OPEN_FAIL_ERROR_NUM) {
                SIGNATURE_TOOLS_LOGE("FILE_OPEN_FAIL_ERROR_NUM");
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
                SIGNATURE_TOOLS_LOGE("getting fileLength failed. fileLength: %{public}lld", fileLength);
                return false;
            }
            return true;
        }
        long long RandomAccessFile::GetLength() const
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
        long long RandomAccessFile::DoMMap(int32_t bufCapacity, long long offset, MmapInfo& mmapInfo)
        {
            if (!CheckLittleEndian()) {
                SIGNATURE_TOOLS_LOGE("CheckLittleEndian: failed");
                return MMAP_FAILED;
            }
            mmapInfo.mapAddr = reinterpret_cast<char*>(MAP_FAILED);                 // mmap addr
            if (fd == FILE_OPEN_FAIL_ERROR_NUM) {
                SIGNATURE_TOOLS_LOGE("FILE_OPEN_FAIL_ERROR_NUM");
                return FILE_IS_CLOSE;
            }
            if (offset < 0 || offset > fileLength - bufCapacity) {
                SIGNATURE_TOOLS_LOGE("offset is less than 0 OR offset is greater than fileLength - bufCapacity");
                return READ_OFFSET_OUT_OF_RANGE;
            }
            // Memory mapped file offset, an integer multiple of 0 or 4K
            mmapInfo.mmapPosition = (offset / memoryPageSize) * memoryPageSize;
            // It can be found by reading as many bytes from the currently mapped memory page
            mmapInfo.readMoreLen = static_cast<int>(offset - mmapInfo.mmapPosition);
            mmapInfo.mmapSize = bufCapacity + mmapInfo.readMoreLen;
            /*
         * #include <sys/mman.h>
         * void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
         * Function is used to create a memory map, map the data of a disk file to memory,
         * and users can modify the disk file by modifying the memory
         * Parameter:
         * addr: The first address of the mapping area.
         * NULL indicates that the operating system selects the start address of the mapping area.
         * This is the most common setting. If addr is not NULL, you specify the start address of the mapping area
         * length: indicates the size of the mapping area, in bytes. Generally, the size of the file is specified
         *   prot:
         * Return: Start address of the mapping area
         */
            mmapInfo.mapAddr = reinterpret_cast<char*>(
                mmap(
                    nullptr,
                    mmapInfo.mmapSize,
                    /* Specify protection requirements for the mapping area.PROT_EXEC:
                    the mapping area can be executed.PROT_READ : The mapping area can be read.PROT_WRITE :
                    The mapping area can be written.
                    PROT_NONE: The mapping area is inaccessible*/
                    PROT_READ | PROT_WRITE,
                    /* Flag bit parameters :MAP_SHARED: Modified memory data will be synchronized to a disk.
                    MAP_POPULATE: Prepare page tables in pre-read mode for file mapping.
                    Subsequent access to the mapping area is not blocked by page violations*/
                    MAP_SHARED | MAP_POPULATE,
                    // The file descriptor, the fd corresponding to the file to be mapped, is obtained using open()
                    fd,
                    /* The offset of the file map,
                    usually set to 0 to indicate that the map starts at the head of the file,
                    must be an integer multiple of 4k or 0 */
                    mmapInfo.mmapPosition)
            );
            if (mmapInfo.mapAddr == MAP_FAILED) {
                SIGNATURE_TOOLS_LOGE("MAP_FAILED");
                return MMAP_FAILED;
            }
            return 0;
        }
        long long RandomAccessFile::ReadFileFullyFromOffset(char buf[], long long offset, int32_t bufCapacity)
        {
            if (buf == nullptr) {
                SIGNATURE_TOOLS_LOGE("DEST_BUFFER_IS_NULL");
                return DEST_BUFFER_IS_NULL;
            }
            MmapInfo mmapInfo;
            long long ret = DoMMap(bufCapacity, offset, mmapInfo);
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
        long long RandomAccessFile::ReadFileFullyFromOffset(ByteBuffer& buffer, long long offset)
        {
            if (!buffer.HasRemaining()) {
                SIGNATURE_TOOLS_LOGE("DEST_BUFFER_IS_NULL");
                return DEST_BUFFER_IS_NULL;
            }
            MmapInfo mmapInfo;
            int32_t bufCapacity = buffer.GetCapacity();
            long long ret = DoMMap(bufCapacity, offset, mmapInfo);
            if (ret < 0) {
                return ret;
            }
            buffer.PutData(0, mmapInfo.mapAddr + mmapInfo.readMoreLen, bufCapacity);
            munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
            return bufCapacity;
        }
        long long  RandomAccessFile::WriteToFile(std::vector<char>& buffer,
            long long index, long long position, long long length)
        {
            // write file, file length may change
            int remainLength = fileLength - position;
            fileLength = (length <= remainLength) ? fileLength : (fileLength + (length - remainLength));
            // update file length
            ftruncate(fd, fileLength);
            if (length == 0) {
                SIGNATURE_TOOLS_LOGE("DEST_BUFFER_IS_NULL");
                return DEST_BUFFER_IS_NULL;
            }
            MmapInfo mmapInfo;
            long long ret = DoMMap(length, position, mmapInfo);
            if (ret < 0) {
                return ret;
            }
            if (memcpy_s(mmapInfo.mapAddr + mmapInfo.readMoreLen, mmapInfo.mmapSize -
                mmapInfo.readMoreLen, buffer.data() + index, buffer.size() - index) != EOK) {
                SIGNATURE_TOOLS_LOGE("WriteToFile memcpy_s failed.\n");
                return ret;
            }
            munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
            return length;
        }
        long long RandomAccessFile::WriteToFile(ByteBuffer& buffer, long long position, long long length)
        {
            // write file, file length may change
            int remainLength = fileLength - position;
            fileLength = (length <= remainLength) ? fileLength : (fileLength + (length - remainLength));
            // update file length
            ftruncate(fd, fileLength);
            int32_t bufCapacity = buffer.GetCapacity();
            if (bufCapacity == 0) {
                SIGNATURE_TOOLS_LOGE("DEST_BUFFER_IS_NULL");
                return DEST_BUFFER_IS_NULL;
            }
            MmapInfo mmapInfo;
            long long ret = DoMMap(bufCapacity, position, mmapInfo);
            if (ret < 0) {
                return ret;
            }
            memcpy_s(mmapInfo.mapAddr + mmapInfo.readMoreLen, mmapInfo.mmapSize - mmapInfo.readMoreLen,
                buffer.GetBufferPtr(), bufCapacity);
            munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
            return bufCapacity;
        }
        bool RandomAccessFile::ReadFileFromOffsetAndDigestUpdate(const DigestParameter& digestParam,
            int32_t chunkSize, long long offset)
        {
            MmapInfo mmapInfo;
            long long ret = DoMMap(chunkSize, offset, mmapInfo);
            if (ret < 0) {
                SIGNATURE_TOOLS_LOGE("DoMMap failed: %{public}lld", ret);
                return false;
            }
            unsigned char* content = reinterpret_cast<unsigned char*>(mmapInfo.mapAddr + mmapInfo.readMoreLen);
            bool res = HapVerifyOpensslUtils::DigestUpdate(digestParam, content, chunkSize);
            munmap(mmapInfo.mapAddr, mmapInfo.mmapSize);
            return res;
        }
    } // namespace SignatureTools
} // namespace OHOS