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
#include <mutex>
#include "random_access_file_zip_data_output.h"
#include "signature_tools_log.h"

using namespace OHOS::SignatureTools;

RandomAccessFileZipDataOutput::RandomAccessFileZipDataOutput(RandomAccessFile* file)
    : RandomAccessFileZipDataOutput(file, 0)
{
}

RandomAccessFileZipDataOutput::RandomAccessFileZipDataOutput(RandomAccessFile* file, long startPosition)
    : file(file)
{
    if (startPosition < 0) {
        SIGNATURE_TOOLS_LOGE("invalide start position: %{public}ld", startPosition);
        return;
    }
    this->position = startPosition;
}

bool RandomAccessFileZipDataOutput::Write(ByteBuffer& buffer)
{
    int length = buffer.GetCapacity();
    if (length == 0) {
        return false;
    }
    {
        std::mutex tmpMutex;
        std::scoped_lock lock(tmpMutex);
        if (file->WriteToFile(buffer, position, length) < 0) return false;
        position += length;
    }
    return true;
}
