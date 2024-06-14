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
#ifndef SIGNATURETOOLS_CODE_SIGNING_H
#define SIGNATURETOOLS_CODE_SIGNING_H

#include <vector>
#include <string>
#include <contrib/minizip/unzip.h>

#include "securec.h"
#include "hap_utils.h"
#include "zip_signer.h"
#include "file_utils.h"
#include "local_signer.h"
#include "signer_config.h"
#include "code_sign_block.h"
#include "signature_tools_log.h"
#include "fs_verity_generator.h"
#include "merkle_tree_extension.h"
#include "bc_signeddata_generator.h"

namespace OHOS {
namespace SignatureTools {
class CodeSigning {
public:
    CodeSigning(SignerConfig* signConfig);
    CodeSigning();
    static const std::vector<std::string> SUPPORT_FILE_FORM;
    static const std::string HAP_SIGNATURE_ENTRY_NAME;
    static const std::string ENABLE_SIGN_CODE_VALUE;
    static const std::string SUPPORT_BIN_FILE_FORM;
    bool GetCodeSignBlock(const std::string input, int64_t offset,
        std::string inForm, std::string profileContent, ZipSigner& zip, std::vector<int8_t>& ret);
    bool SignFile(std::istream& inputStream,
        int64_t fileSize, bool storeTree, int64_t fsvTreeOffset, std::string ownerID,
        std::pair<SignInfo, std::vector<int8_t>>& ret);
    std::vector<int8_t> GetElfCodeSignBlock(std::string input, int64_t offset,
        std::string inForm, std::string profileContent);

public:
    const std::string NATIVE_LIB_AN_SUFFIX = ".an";
    const std::string NATIVE_LIB_SO_SUFFIX = ".so";
    int64_t timestamp = 0;
    std::vector<std::string> extractedNativeLibSuffixs;
    SignerConfig* signConfig;
    CodeSignBlock codeSignBlock;
    int64_t ComputeDataSize(ZipSigner& zip);
    int64_t GetTimestamp();
    bool SignNativeLibs(std::string input, std::string ownerID);
    void UpdateCodeSignBlock();
    static std::vector<std::tuple<std::string, std::stringbuf, uLong>> GetNativeEntriesFromHap(
        std::string& packageName);
    static std::string SplitFileName(const std::string& path);
    static bool IsNativeFile(std::string& input);
    bool SignFilesFromJar(std::vector<std::tuple<std::string,
        std::stringbuf, uLong>>&,
        std::string&, const std::string&,
        std::vector<std::pair<std::string, SignInfo>>&);
    bool GenerateSignature(std::vector<int8_t>& signedData, const std::string&,
        std::vector<int8_t>&);

private:
    static bool HandleZipGlobalInfo(unzFile& zFile, unz_global_info& zGlobalInfo,
        std::vector<std::tuple<std::string, std::stringbuf, uLong>>& result);
    static bool CheckUnzParam(unzFile& zFile, unz_file_info& zFileInfo, char fileName[], size_t* nameLen);
    static bool CheckFileName(unzFile& zFile, char fileName[], size_t* nameLen);
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATURETOOLS_CODE_SIGNING_H