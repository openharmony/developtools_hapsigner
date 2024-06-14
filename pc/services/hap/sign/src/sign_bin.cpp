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

#include "sign_bin.h"
#include "param_constants.h"
#include "file_utils.h"
#include "hw_block_head.h"
#include "signature_block_types.h"
#include "signature_block_tags.h"
#include "hash_utils.h"
#include "sign_content_info.h"
#include "hw_sign_head.h"
#include "bc_pkcs7_generator.h"
#include "params.h"

namespace OHOS {
namespace SignatureTools {

bool SignBin::Sign(SignerConfig& signerConfig, const std::map<std::string, std::string>& signParams)
{
    /* 1. Make block head, write to output file. */
    std::string signCode = signParams.at(ParamConstants::PARAM_SIGN_CODE);
    if (ParamConstants::ENABLE_SIGN_CODE == signCode) {
        SIGNATURE_TOOLS_LOGW("can not sign bin with codesign.\n");
    }
    std::string inputFile = signParams.at(ParamConstants::PARAM_BASIC_INPUT_FILE);
    std::string outputFile = signParams.at(ParamConstants::PARAM_BASIC_OUTPUT_FILE);
    std::string profileFile = signParams.at(ParamConstants::PARAM_BASIC_PROFILE);
    std::string profileSigned = signParams.at(ParamConstants::PARAM_BASIC_PROFILE_SIGNED);
    if (!WriteBlockDataToFile(inputFile, outputFile, profileFile, profileSigned)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "The block head data made failed.");
        FileUtils::DelDir(outputFile);
        return false;
    }
    /* 2. Make sign data, and append write to output file */
    std::string signAlg = signParams.at(ParamConstants::PARAM_BASIC_SIGANTURE_ALG);
    if (!WriteSignDataToOutputFile(signerConfig, outputFile, signAlg)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "The sign data made failed.");
        FileUtils::DelDir(outputFile);
        return false;
    }
    /* 3. Make sign head data, and write to output file */
    if (!WriteSignHeadDataToOutputFile(inputFile, outputFile)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "The sign head data made failed.");
        FileUtils::DelDir(outputFile);
        return false;
    }
    return true;
}

bool SignBin::WriteBlockDataToFile(const std::string& inputFile, const std::string& outputFile,
                                   const std::string& profileFile, const std::string& profileSigned)
{
    int64_t binFileLen = FileUtils::GetFileLen(inputFile);
    int64_t profileDataLen = FileUtils::GetFileLen(profileFile);
    if (!CheckBinAndProfileLengthIsValid(binFileLen, profileDataLen)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR,
                            "file length is invalid, binFileLen: " + std::to_string(binFileLen) +
                            "lld, profileDataLen: " + std::to_string(profileDataLen) + "lld");
        return false;
    }
    int64_t offset = binFileLen + HwBlockHead::GetBlockLen() + HwBlockHead::GetBlockLen();
    if (IsLongOverflowInteger(offset)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "The profile block head offset is overflow integer range.");
        return false;
    }
    char isSigned = SignatureBlockTypes::GetProfileBlockTypes(profileSigned);
    std::string proBlockByte =
        HwBlockHead::GetBlockHead(isSigned, SignatureBlockTags::DEFAULT, (short)profileDataLen, (int)offset);
    offset += profileDataLen;
    if (IsLongOverflowInteger(offset)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "The sign block head offset is overflow integer range.");
        return false;
    }
    std::string signBlockByte = HwBlockHead::GetBlockHead(
        SignatureBlockTypes::SIGNATURE_BLOCK, SignatureBlockTags::DEFAULT, (short)0, (int)offset);
    return WriteSignedBin(inputFile, proBlockByte, signBlockByte, profileFile, outputFile);
}

std::vector<int8_t> SignBin::GenerateFileDigest(const std::string& outputFile,
                                                const std::string& signAlg)
{
    SignatureAlgorithmHelper signatureAlgorithmClass;
    if (!Params::GetSignatureAlgorithm(signAlg, signatureAlgorithmClass)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignHap] get Signature Algorithm failed.");
        return std::vector<int8_t>();
    }
    std::string alg = signatureAlgorithmClass.contentDigestAlgorithm.GetDigestAlgorithm();
    std::vector<int8_t> data = HashUtils::GetFileDigest(outputFile, alg);
    if (data.empty()) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "GetFileDigest failed.");
        return std::vector<int8_t>();
    }
    std::vector<int8_t> outputChunk;
    SignContentInfo contentInfo;
    contentInfo.AddContentHashData(0, SignatureBlockTags::HASH_ROOT_4K, HashUtils::GetHashAlgsId(alg),
                                   data.size(), data);
    std::vector<int8_t> dig = contentInfo.GetByteContent();
    if (dig.empty()) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "generate file digest is null.");
        return std::vector<int8_t>();
    }
    return dig;
}

bool SignBin::WriteSignDataToOutputFile(SignerConfig& SignerConfig, const std::string& outputFile,
                                        const std::string& signAlg)
{
    std::vector<int8_t> dig = GenerateFileDigest(outputFile, signAlg);
    if (dig.empty()) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "generateSignature Verity digest is null.");
        return false;
    }
    std::string ret_str;
    std::string signed_data(dig.begin(), dig.end());
    std::unique_ptr<Pkcs7Generator> generator = std::make_unique<BCPkcs7Generator>();
    if (generator->GenerateSignedData(signed_data, &SignerConfig, ret_str)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "failed to GenerateSignedData!");
        return false;
    }
    bool writeByteToOutFile = FileUtils::AppendWriteByteToFile(ret_str, outputFile);
    if (!writeByteToOutFile) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "write signedData to outputFile failed!");
        return false;
    }
    return true;
}

bool SignBin::WriteSignHeadDataToOutputFile(const std::string& inputFile, const std::string& outputFile)
{
    int64_t size = FileUtils::GetFileLen(outputFile) - FileUtils::GetFileLen(inputFile) + HwSignHead::SIGN_HEAD_LEN;
    if (IsLongOverflowInteger(size)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "File size is Overflow integer range!");
        return false;
    }
    HwSignHead signHeadData;
    std::vector<int8_t> signHeadByte = signHeadData.GetSignHead(size);
    if (signHeadByte.empty()) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Failed to get sign head data!");
        return false;
    }
    bool writeByteToOutFile =
        FileUtils::AppendWriteByteToFile(std::string(signHeadByte.begin(), signHeadByte.end()), outputFile);
    if (!writeByteToOutFile) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Failed to WriteByteToOutFile!");
        return false;
    }
    return true;
}

bool SignBin::CheckBinAndProfileLengthIsValid(int64_t binFileLen, int64_t profileDataLen)
{
    return binFileLen != -1 && profileDataLen != -1 && !IsLongOverflowShort(profileDataLen);
}

bool SignBin::IsLongOverflowInteger(int64_t num)
{
    return (num - (num & 0xffffffffL)) != 0;
}

bool SignBin::IsLongOverflowShort(int64_t num)
{
    return (num - (num & 0xffff)) != 0;
}

bool SignBin::WriteSignedBin(const std::string& inputFile, const std::string& proBlockByte,
                             const std::string& signBlockByte, const std::string& profileFile,
                             const std::string& outputFile)
{
    // 1. write the input file to the output file.
    if (!FileUtils::WriteInputToOutPut(inputFile, outputFile)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Failed to write information of input file: " + inputFile +
                            "s to output file: " + outputFile + "s");
        return false;
    }
    // 2. append write profile block head to the output file.
    if (!FileUtils::AppendWriteByteToFile(proBlockByte, outputFile)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Failed to append write proBlockByte to output file: " +
                            outputFile + "s");
        return false;
    }
    // 3. append write sign block head to the output file.
    if (!FileUtils::AppendWriteByteToFile(signBlockByte, outputFile)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Failed to append write binBlockByte to output file: " +
                            outputFile + "s");
        return false;
    }
    // 4. write profile src file to the output file.
    if (!FileUtils::AppendWriteFileToFile(profileFile, outputFile)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Failed to write profile file " + profileFile + "s");
        return false;
    }
    return true;
}

} // namespace SignatureTools
} // namespace OHOS