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

#ifndef SIGNERTOOLS_ZIP_ENTRY_H
#define SIGNERTOOLS_ZIP_ENTRY_H

#include <vector>
#include "zip_entry_data.h"
#include "central_directory.h"

namespace OHOS {
    namespace SignatureTools {
        class ZipEntry {
        private:
            ZipEntryData* zipEntryData;

            CentralDirectory* fileEntryIncentralDirectory;

            /**
             * alignment one entry
             *
             * @param alignNum  need align bytes length
             * @return add bytes length
             * @throws ZipException alignment exception
             */
        public:
            ~ZipEntry()
            {
                delete zipEntryData;
                delete fileEntryIncentralDirectory;
            }

            int Alignment(int alignNum);

        private:
            int CalZeroPaddingLengthForEntryExtra();

            void SetCenterDirectoryNewExtraLength(int newLength);

            void SetEntryHeaderNewExtraLength(int newLength);

            std::vector<char> GetAlignmentNewExtra(int newLength, std::vector<char>& old);

        public:
            ZipEntryData* GetZipEntryData();

            void SetZipEntryData(ZipEntryData* zipEntryData);

            CentralDirectory* GetCentralDirectory();

            void SetCentralDirectory(CentralDirectory* centralDirectory);
        };
    }
}
#endif
