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

#include "verify_bin.h"
#include "verify_hap.h"

namespace OHOS {
namespace SignatureTools {
    
bool VerifyBin::Verify(Options* options)
{
    // check param
    if (options == nullptr) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "Param options is null.");
        return false;
    }
    if (!VerifyElf::CheckParams(options)) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "Check params failed!");
        return false;
    }
    std::string filePath = options->GetString(Options::IN_FILE);
    bool checkSignFileFlag = VerifyElf::CheckSignFile(filePath);
    if (!checkSignFileFlag) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "Check input signature elf false!");
        return false;
    }
    // verify bin
    HapVerifyResult verifyResult;
    Pkcs7Context pkcs7Context;
    bool verifyBinFileFLag = VerifyBinFile(filePath, verifyResult, options, pkcs7Context);
    if (!verifyBinFileFLag) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "Verify bin file failed!");
        return false;
    }
    // write certificate and p7b file
    VerifyHap hapVerifyV2;
    int32_t writeVerifyOutputFlag = hapVerifyV2.WriteVerifyOutput(pkcs7Context, options);
    if (writeVerifyOutputFlag != VERIFY_SUCCESS) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "Verify bin WriteVerifyOutput failed!");
        return false;
    }
    return true;
}

bool VerifyBin::VerifyBinFile(const std::string& binFile, HapVerifyResult& verifyResult,
                              Options* options, Pkcs7Context& pkcs7Context)
{
    SignBlockInfo signBlockInfo(true);
    bool getSignBlockInfoFlag = VerifyElf::GetSignBlockInfo(binFile, signBlockInfo, VerifyElf::BIN_FILE_TYPE);
    if (!getSignBlockInfoFlag) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "VerifyBinFile GetSignBlockInfo failed!");
        return false;
    }
    // verify profile
    std::string profileJson;
    bool verifyP7bFlag = VerifyElf::VerifyP7b(signBlockInfo.GetSignBlockMap(), options, pkcs7Context,
        verifyResult, profileJson);
    if (!verifyP7bFlag) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "VerifyBinFile VerifyProfile failed!");
        return false;
    }
    // verify signed data
    bool verifyBinDigestFlag = VerifyBinDigest(signBlockInfo);
    if (!verifyBinDigestFlag) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "VerifyBinFile VerifyBinDigest failed!");
        return false;
    }
    return true;
}

bool VerifyBin::VerifyBinDigest(SignBlockInfo& signBlockInfo)
{
    std::vector<int8_t> rawDigest = signBlockInfo.GetRawDigest();
    std::vector<int8_t> generatedDig = signBlockInfo.GetFileDigest();
    bool isEqual = rawDigest.empty() || generatedDig.empty() ||
        !std::equal(rawDigest.begin(), rawDigest.end(), generatedDig.begin());
    if (isEqual) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "VerifyBinDigest verify digest failed!");
        return false;
    }
    return true;
}

} // namespace SignatureTools
} // namespace OHOS