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

#ifndef SIGNERTOOLS_RANDOMACCESSFILE_ZIPDATA_INPUT_H
#define SIGNERTOOLS_RANDOMACCESSFILE_ZIPDATA_INPUT_H
#include "signature_tools_log.h"
#include "zip_data_input.h"
#include "random_access_file.h"
#include "file_data_source.h"

namespace OHOS {
    namespace SignatureTools {
        class RandomAccessFileZipDataInput : public ZipDataInput {
        private:
            static constexpr int MAX_READ_BLOCK_SIZE = 1024 * 1024;

            RandomAccessFile& file;

            const long  startIndex;

            const long  size;

            /**
             * Random Access File Zip Data Input
             *
             * @param file zip file
             */
        public:
            ~RandomAccessFileZipDataInput()
            {
            }

            RandomAccessFileZipDataInput(RandomAccessFile& file);

            /**
             * Random Access File Zip Data Input
             *
             * @param file zip file
             * @param offset offset
             * @param size size
             */
            RandomAccessFileZipDataInput(RandomAccessFile& file, long  offset, long  size);

            long Size() override;

            bool CopyTo(long  offset, int size, ByteBuffer& buffer) override;

            ByteBuffer CreateByteBuffer(long  offset, int size) override;

            DataSource* Slice(long offset, long size) override;

        private:
            bool CheckBoundValid(long  offset, long  size, long  sourceSize);
        };
    }
}
#endif
