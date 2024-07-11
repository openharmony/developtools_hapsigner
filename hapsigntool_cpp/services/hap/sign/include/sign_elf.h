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

#ifndef SIGNATRUETOOLS_SIGH_ELF_H
#define SIGNATRUETOOLS_SIGH_ELF_H

#include <list>
#include <ctime>
#include <string>
#include <chrono>
#include <vector>

#include "signer_config.h"
#include "sign_block_data.h"
#include "hap_signer_block_utils.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {
class SignElf {
public:
    static const char CODESIGN_BLOCK_TYPE = 3;
    static bool Sign(SignerConfig& signerConfig, std::map<std::string, std::string> &signParams);

private:
    static int blockNum;
    static constexpr int PAGE_SIZE = 4096;
    static constexpr int FILE_BUFFER_BLOCK = 16384;
    static const std::string CODESIGN_OFF;

    static bool AlignFileBy4kBytes(std::string& inputFile, std::string& tmp);
    static bool WriteBlockDataToFile(SignerConfig& signerConfig,
                                     std::string inputFile, std::string outputFile,
                                     std::string profileSigned,
                                     std::map<std::string, std::string> signParams);
    static bool WriteSignedElf(std::string inputFile,
                               std::list<SignBlockData>& signBlockList, std::string outputFile);
    static bool WriteSignBlockData(std::list<SignBlockData>& signBlockList, std::ofstream& fileOutputStream);
    static bool GenerateSignBlockHead(std::list<SignBlockData>& signDataList);
    static SignBlockData GenerateProfileSignByte(std::string profileFile, std::string profileSigned);
    static bool GenerateCodeSignByte(SignerConfig& signerConfig, std::map<std::string, std::string> signParams,
                                     std::string inputFile, int blockNum,
                                     long binFileLen, SignBlockData** codeSign);
    static bool WriteSignHeadDataToOutputFile(std::string inputFile, std::string outputFile, int blockNum);
    static bool IsLongOverflowInteger(int64_t num);
    static bool IsLongOverflowShort(int64_t num);
};
} // namespace SignatureTools
} // namespace OHOS
#endif
