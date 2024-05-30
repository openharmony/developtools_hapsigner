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
#ifndef SIGNATURETOOLS_CODE_SIGNING_H
#define SIGNATURETOOLS_CODE_SIGNING_H
#include <vector>
#include <string>
#include "securec.h"
#include "signature_tools_log.h"
#include "signer_config.h"
#include "code_sign_block.h"
#include "merkle_tree_extension.h"
#include "local_signer.h"
#include "zip_signer.h"
#include "file_utils.h"
#include "fs_verity_generator.h"
#include "bc_signeddata_generator.h"
#include "hap_utils.h"
#include <contrib/minizip/unzip.h>
namespace OHOS {
    namespace SignatureTools {
        class CodeSigning {
        public:
            CodeSigning(SignerConfig signConfig);
            CodeSigning();
            static const std::vector<std::string> SUPPORT_FILE_FORM;
            static const std::string HAP_SIGNATURE_ENTRY_NAME;
            static const std::string ENABLE_SIGN_CODE_VALUE;
            bool getCodeSignBlock(const std::string input, int64_t offset,
                std::string inForm, std::string profileContent, Zip& zip, std::vector<int8_t>& ret);
            bool signFile(std::istream& inputStream,
                int64_t fileSize, bool storeTree, int64_t fsvTreeOffset, std::string ownerID,
                std::pair<SignInfo, std::vector<int8_t>>& ret);
        public:
            const std::string NATIVE_LIB_AN_SUFFIX = ".an";
            const std::string NATIVE_LIB_SO_SUFFIX = ".so";
            int64_t timestamp = 0;
            std::vector<std::string> extractedNativeLibSuffixs;
            SignerConfig signConfig;
            CodeSignBlock codeSignBlock;
            int64_t computeDataSize(Zip& zip);
            int64_t getTimestamp();
            bool signNativeLibs(std::string input, std::string ownerID);
            void updateCodeSignBlock();
            static std::vector<std::tuple<std::string, std::stringbuf, uLong>> GetNativeEntriesFromHap(
                std::string& packageName);
            static std::string splitFileName(const std::string& path);
            static bool isNativeFile(std::string& input);
            bool SignFilesFromJar(std::vector<std::tuple<std::string,
                std::stringbuf, uLong>>& entryNames, std::string& packageName, const std::string& ownerID,
                std::vector<std::pair<std::string, SignInfo>>& ret);
            bool generateSignature(std::vector<int8_t>& signedData, const std::string& ownerID,
                std::vector<int8_t>& ret);
        private:
            static bool handleZipGlobalInfo(unzFile& zFile, unz_global_info& zGlobalInfo, char* szReadBuffer,
                std::vector<std::tuple<std::string, std::stringbuf, uLong>>& result);
            static bool checkUnzParam(unzFile& zFile, unz_file_info& zFileInfo, char* fileName, size_t* nameLen);
            static bool checkFileName(unzFile& zFile, char* fileName, size_t* nameLen);
        };
    }
}
#endif