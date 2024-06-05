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

#ifndef SIGNERTOOLS_ZIP_H
#define SIGNERTOOLS_ZIP_H

#include <optional>
#include <fstream>
#include <string>
#include <vector>
#include "endof_central_directory.h"
#include "zip_entry.h"
#include "signature_tools_log.h"

namespace OHOS {
    namespace SignatureTools {
        class Zip {
        public:
            /**
             * file is uncompress file flag
             */
            static constexpr int FILE_UNCOMPRESS_METHOD_FLAG = 0;

            /**
             * max comment length
             */
            static constexpr int MAX_COMMENT_LENGTH = 65535;

        private:
            std::vector<ZipEntry*> zipEntries;

            uint64_t signingOffset = 0;

            std::vector<char> signingBlock;

            uint64_t cDOffset = 0;

            uint64_t eOCDOffset = 0;

            EndOfCentralDirectory* endOfCentralDirectory;

            /**
             * create Zip by file
             *
             * @param inputFile file
             */
        public:
            ~Zip()
            {
                delete endOfCentralDirectory;
                for (ZipEntry* zipEntry : zipEntries) {
                    delete zipEntry;
                }
            }
            Zip()
            {
            }
            bool Init(std::ifstream& inputFile);

        private:
            EndOfCentralDirectory* GetZipEndOfCentralDirectory(std::ifstream& input);

            bool GetZipCentralDirectory(std::ifstream& input);

            std::vector<char> GetSigningBlock(std::ifstream& input);

            bool GetZipEntries(std::ifstream& input);

            /**
             * output zip to zip file
             *
             * @param outFile file path
             */
        public:
            bool ToFile(std::ifstream& input, std::ofstream& output);

            /**
             * alignment uncompress entry
             *
             * @param alignment int alignment
             */
            void Alignment(int alignment);

            /**
             * remove sign block
             */
            void RemoveSignBlock();

            /**
             * sort uncompress entry in the front.
             */
        private:
            void Sort();

            void ResetOffset();

        public:
            std::vector<ZipEntry*>& GetZipEntries();

            uint64_t GetSigningOffset();

            uint64_t GetCDOffset();

            uint64_t GetEOCDOffset();

            EndOfCentralDirectory* GetEndOfCentralDirectory();
        };
    }
}
#endif
