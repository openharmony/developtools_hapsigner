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

#ifndef SIGNERTOOLS_ZIP_ENTRYDATA_H
#define SIGNERTOOLS_ZIP_ENTRYDATA_H

#include <string>

#include "zip_entry_header.h"
#include "data_descriptor.h"

namespace OHOS {
    namespace SignatureTools {
        class ZipEntryData {
            /**
             * data descriptor has or not mask
             */
        public:
            static constexpr short HAS_DATA_DESCRIPTOR_MASK = 0x08;

            /**
             * data descriptor has or not flag mask
             */
            static constexpr short NOT_HAS_DATA_DESCRIPTOR_FLAG = 0;

        private:
            ZipEntryHeader* zipEntryHeader;

            long fileOffset = 0;

            long fileSize = 0;

            DataDescriptor* dataDescriptor;

            long length = 0;

        public:
            ~ZipEntryData()
            {
                delete zipEntryHeader;
                delete dataDescriptor;
            }

            ZipEntryHeader* GetZipEntryHeader();

            /**
             * init zip entry by file
             *
             * @param file zip file
             * @param entryOffset entry start offset
             * @param fileSize compress file size
             * @return zip entry
             * @throws IOException read zip exception
             */
            static ZipEntryData* GetZipEntry(std::ifstream& input, long long entryOffset, long long fileSize);

            void SetZipEntryHeader(ZipEntryHeader* zipEntryHeader);

            DataDescriptor* GetDataDescriptor();

            void SetDataDescriptor(DataDescriptor* dataDescriptor);

            long GetFileOffset();

            void SetFileOffset(long fileOffset);

            long GetFileSize();

            void SetFileSize(long fileSize);

            long GetLength();

            void SetLength(long length);

        private:
            static bool ReadEntryFileNameAndExtraByOffset(std::ifstream &input,
                                                          ZipEntryHeader *entryHeader,
                                                          long long &offset);
        };
    }
}
#endif
