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

#include "verify_bin.h"
#include "hap_verify_v2.h"

using namespace OHOS::SignatureTools;

bool VerifyBin::Verify(Options* options)
{
    // check param
    if (options == nullptr) {
        SIGNATURE_TOOLS_LOGE("Param options is null.\n");
        return false;
    }
    if (!VerifyElf::CheckParams(options)) {
        SIGNATURE_TOOLS_LOGE("Check params failed!\n");
        return false;
    }
    std::string filePath = options->GetString(Options::IN_FILE);
    if (!VerifyElf::CheckSignFile(filePath)) {
        SIGNATURE_TOOLS_LOGE("Check input signature elf false!\n");
        return false;
    }
    // verify bin
    HapVerifyResult verifyResult;
    Pkcs7Context pkcs7Context;
    if (!VerifyBinFile(filePath, verifyResult, options, pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("Verify bin file failed!\n");
        return false;
    }
    // write certificate and p7b file
    HapVerifyV2 hapVerifyV2;
    if (hapVerifyV2.WriteVerifyOutput(pkcs7Context, options) != VERIFY_SUCCESS) {
        SIGNATURE_TOOLS_LOGE("Verify bin WriteVerifyOutput failed!\n");
        return false;
    }
    return true;
}

bool VerifyBin::VerifyBinFile(const std::string& binFile, HapVerifyResult& verifyResult,
    Options* options, Pkcs7Context& pkcs7Context)
{
    SignBlockInfo signBlockInfo(true);
    if (!VerifyElf::GetSignBlockInfo(binFile, signBlockInfo, VerifyElf::BIN_FILE_TYPE)) {
        SIGNATURE_TOOLS_LOGE("VerifyBinFile GetSignBlockInfo failed!\n");
        return false;
    }
    // verify profile
    std::string profileJson;
    if (!VerifyElf::VerifyP7b(signBlockInfo.GetSignBlockMap(), options, pkcs7Context,
        verifyResult, profileJson)) {
        SIGNATURE_TOOLS_LOGE("VerifyBinFile VerifyProfile failed!\n");
        return false;
    }
    // verify signed data
    if (!VerifyBinDigest(signBlockInfo)) {
        SIGNATURE_TOOLS_LOGE("VerifyBinFile VerifyBinDigest failed!\n");
        return false;
    }
    return true;
}

bool VerifyBin::VerifyBinDigest(SignBlockInfo& signBlockInfo)
{
    std::vector<int8_t> rawDigest = signBlockInfo.GetRawDigest();
    std::vector<int8_t> generatedDig = signBlockInfo.GetFileDigest();
    if (rawDigest.empty() || generatedDig.empty() ||
        !std::equal(rawDigest.begin(), rawDigest.end(), generatedDig.begin())) {
        SIGNATURE_TOOLS_LOGE("VerifyBinDigest verify digest failed!\n");
        return false;
    }
    return true;
}