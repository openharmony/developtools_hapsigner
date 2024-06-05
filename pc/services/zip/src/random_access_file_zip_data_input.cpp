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
#include <string>
#include <stdexcept>
#include <algorithm>
#include <mutex>
#include "random_access_file_zip_data_input.h"

using namespace OHOS::SignatureTools;

RandomAccessFileZipDataInput::RandomAccessFileZipDataInput(RandomAccessFile &file)
    : file(file), startIndex(0), size(-1)
{
}

RandomAccessFileZipDataInput::RandomAccessFileZipDataInput(RandomAccessFile &file, long offset, long size)
    : file(file), startIndex(offset), size(size)
{
    if (offset < 0) {
        SIGNATURE_TOOLS_LOGE("out of range: offset %{public}ld", offset);
        return;
    }
    if (size < 0) {
        SIGNATURE_TOOLS_LOGE("out of range: size %{public}ld", size);
        return;
    }
}

long RandomAccessFileZipDataInput::Size()
{
    if (size == -1) {
        return file.GetLength();
    }
    return size;
}

bool RandomAccessFileZipDataInput::CopyTo(long offset, int size, ByteBuffer &buffer)
{
    long srcSize = this->Size();
    if (!CheckBoundValid(offset, size, srcSize)) {
        return false;
    }
    if (size == 0) {
        SIGNATURE_TOOLS_LOGE("size = 0");
        return false;
    }
    if (size > buffer.Remaining()) {
        SIGNATURE_TOOLS_LOGE("The length size passed in is greater than the reserved length of ByteBuffer");
        return false;
    }
    long offsetInFile = startIndex + offset;
    int remaining = size;
    int originalLimit = buffer.GetLimit();

    buffer.SetLimit(buffer.GetPosition() + size);
    int readSize;
    while (remaining > 0) {
        {
            std::mutex tmpMutex;
            std::scoped_lock lock(tmpMutex);
            readSize = file.ReadFileFullyFromOffset(buffer, offsetInFile);
        }
        offsetInFile += readSize;
        remaining -= readSize;
    }
    int cap = buffer.GetCapacity();
    buffer.SetPosition(cap);
    buffer.SetLimit(originalLimit);
    return true;
}

ByteBuffer RandomAccessFileZipDataInput::CreateByteBuffer(long offset, int size)
{
    ByteBuffer byteBuffer;
    if (size < 0) {
        SIGNATURE_TOOLS_LOGE("size < 0");
        return byteBuffer;
    }

    byteBuffer.SetCapacity(size);
    CopyTo(offset, size, byteBuffer);

    return byteBuffer.Flip();
}

DataSource *RandomAccessFileZipDataInput::Slice(long offset, long size)
{
    long long srcSize = this->Size();
    if (!CheckBoundValid(offset, size, srcSize)) {
        return nullptr;
    }
    if (offset == 0 && size == srcSize) {
        SIGNATURE_TOOLS_LOGE("offset = 0, size = %{public}ld", size);
        return new HapFileDataSource(file, startIndex, size, 0);
    }
    return new HapFileDataSource(file, offset, size, 0);
}

bool RandomAccessFileZipDataInput::CheckBoundValid(long offset, long size, long sourceSize)
{
    if (offset < 0) {
        SIGNATURE_TOOLS_LOGE("out of range: offset %{public}ld", offset);
        return false;
    }
    if (size < 0) {
        SIGNATURE_TOOLS_LOGE("out of range: size %{public}ld", size);
        return false;
    }
    if (offset > sourceSize) {
        SIGNATURE_TOOLS_LOGE("out of range: offset %{public}ld is greater than sourceSize %{public}ld",
                             offset, sourceSize);
        return false;
    }
    long long endOffset = offset + size;
    if (endOffset < offset) {
        SIGNATURE_TOOLS_LOGE("out of range: offset %{public}ld add size %{public}ld is overflow",
                             offset, size);
        return false;
    }
    if (endOffset > sourceSize) {
        SIGNATURE_TOOLS_LOGE("out of range: offset %{public}ld add size %{public}ld is greater than" \
                             "sourceSize %{public}ld", offset, size, sourceSize);
        return false;
    }
    return true;
}