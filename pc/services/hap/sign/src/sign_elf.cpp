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

#include "sign_elf.h"
#include "string_utils.h"
#include "code_signing.h"
#include "param_constants.h"
#include "hw_block_head.h"
#include "hw_sign_head.h"
#include "signature_block_types.h"
#include "signature_block_tags.h"

namespace OHOS {
namespace SignatureTools {

int SignElf::blockNum = 0;
const int SignElf::PAGE_SIZE = 4096;
const int SignElf::FILE_BUFFER_BLOCK = 16384;
const std::string SignElf::CODESIGN_OFF = "0";

bool SignElf::Sign(SignerConfig signerConfig, std::map<std::string, std::string> signParams)
{
    std::string inputFile = signParams.at(ParamConstants::PARAM_BASIC_INPUT_FILE);
    std::string tmpFile;
    bool checkAlignFileBy4kBytesFlag = AlignFileBy4kBytes(inputFile, tmpFile);
    if (!checkAlignFileBy4kBytesFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] alignFileBy4kBytes error.");
        remove(tmpFile.c_str());
        return false;
    }
    std::string outputFile = signParams.at(ParamConstants::PARAM_BASIC_OUTPUT_FILE);
    std::string profileSigned = signParams.at(ParamConstants::PARAM_BASIC_PROFILE_SIGNED);
    bool checkWriteBlockDataToFileFlag = WriteBlockDataToFile(signerConfig, tmpFile,
                                                              outputFile, profileSigned, signParams);
    if (!checkWriteBlockDataToFileFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] writeBlockDataToFile error.");
        remove(tmpFile.c_str());
        return false;
    }
    bool checkWriteSignHeadDataToOutputFileFlag = WriteSignHeadDataToOutputFile(tmpFile, outputFile, blockNum);
    if (!checkWriteSignHeadDataToOutputFileFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] The sign head data made failed.");
        remove(tmpFile.c_str());
        return false;
    }
    return (remove(tmpFile.c_str()) == 0);
    ;
}

bool SignElf::AlignFileBy4kBytes(std::string& inputFile, std::string& ret)
{
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    std::string tmp = "tmpFile" + std::to_string(timestamp);
    std::ofstream output(tmp);
    bool checkoutputFlag = output.is_open();
    if (!checkoutputFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] unable to open " + tmp + "s.");
        return false;
    }
    std::ifstream input(inputFile);
    bool checkinputFlag = input.is_open();
    if (!checkinputFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] unable to open " + inputFile + "s.");
        return false;
    }
    char buffer[FILE_BUFFER_BLOCK];
    std::streamsize bytesRead;
    int64_t output_length = 0;
    while ((bytesRead = input.read(buffer, sizeof(buffer)).gcount()) > 0) {
        output.write(buffer, bytesRead);
        output_length += bytesRead;
    }
    int64_t addLength = PAGE_SIZE - (output_length % PAGE_SIZE);
    std::vector<char> bytes(addLength, 0);
    output.write(bytes.data(), addLength);
    ret = tmp;
    return true;
}

bool SignElf::WriteBlockDataToFile(SignerConfig signerConfig,
                                   std::string inputFile, std::string outputFile, std::string profileSigned,
                                   std::map<std::string, std::string> signParams)
{
    std::string profiliFile = signParams.at(ParamConstants::PARAM_BASIC_PROFILE);
    std::list<SignBlockData> signDataList;
    int64_t binFileLen = FileUtils::GetFileLen(inputFile);
    bool checkFlag = binFileLen < 0 || IsLongOverflowInteger(binFileLen);
    if (checkFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] getFileLen or isLongOverflowInteger error.");
        return false;
    }
    bool checkIsEmptyFlag = StringUtils::IsEmpty(signParams.at(ParamConstants::PARAM_BASIC_PROFILE));
    if (!checkIsEmptyFlag) {
        signDataList.push_front(GenerateProfileSignByte(profiliFile, profileSigned));
    }
    blockNum = signDataList.size() + 1;
    SignBlockData* codeSign = nullptr;
    bool checkGenerateCodeSignByteFlag = !GenerateCodeSignByte(signerConfig, signParams, inputFile, blockNum,
                                                               binFileLen, &codeSign) || !codeSign;
    if (checkGenerateCodeSignByteFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] generateCodeSignByte error.");
        if (codeSign) {
            delete codeSign;
        }
        return false;
    }
    signDataList.push_front(*codeSign);
    blockNum = signDataList.size();
    bool checkGenerateSignBlockHeadFlag = GenerateSignBlockHead(signDataList);
    if (!checkGenerateSignBlockHeadFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] generateSignBlockHead error.");
        delete codeSign;
        return false;
    }
    delete codeSign;
    return WriteSignedElf(inputFile, signDataList, outputFile);
}

bool SignElf::WriteSignedElf(std::string inputFile, std::list<SignBlockData>& signBlockList, std::string outputFile)
{
    std::ifstream fileInputStream(inputFile, std::ios::binary);
    std::ofstream fileOutputStream(outputFile, std::ios::binary);
    bool checkFlag = !fileInputStream.is_open() || !fileOutputStream.is_open();
    if (checkFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] inputFile or outputFile open error.");
        return false;
    }
    char buffer[FILE_BUFFER_BLOCK];
    while (!fileInputStream.eof()) {
        fileInputStream.read(buffer, sizeof(buffer));
        fileOutputStream.write(buffer, fileInputStream.gcount());
    }
    for (auto signBlockData : signBlockList) {
        bool checkWriteByteToOutFileFlag = FileUtils::WriteByteToOutFile(signBlockData.GetBlockHead(),
                                                                         fileOutputStream);
        if (!checkWriteByteToOutFileFlag) {
            PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Failed to write Block Head to output file.");
            fileInputStream.close();
            fileOutputStream.close();
            return false;
        }
    }
    for (auto signBlockData : signBlockList) {
        bool isSuccess;
        checkFlag = signBlockData.GetByte();
        if (checkFlag) {
            isSuccess = FileUtils::WriteByteToOutFile(signBlockData.GetSignData(), fileOutputStream);
        } else {
            std::ifstream InputSignFileStream(signBlockData.GetSignFile(), std::ios::binary);
            bool checkFileFlag = !InputSignFileStream.is_open();
            if (checkFileFlag) {
                PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] InputSignFileStream open error.");
                return false;
            }
            int result = FileUtils::WriteInputToOutPut(InputSignFileStream, fileOutputStream,
                                                       (long)signBlockData.GetLen());
            isSuccess = (result == 0 ? true : false);
        }
        if (!isSuccess) {
            PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "Failed to WriteByteToOutFile.");
            fileInputStream.close();
            fileOutputStream.close();
            return false;
        }
    }
    fileInputStream.close();
    fileOutputStream.close();
    return true;
}

bool SignElf::GenerateSignBlockHead(std::list<SignBlockData>& signDataList)
{
    int64_t offset = HwBlockHead::GetElfBlockLen() * signDataList.size();
    for (std::list<SignBlockData>::iterator it = signDataList.begin(); it != signDataList.end(); ++it) {
        std::vector<int8_t> tmp = HwBlockHead::GetBlockHeadLittleEndian(it->GetType(),
                                                                        SignatureBlockTags::DEFAULT,
                                                                        it->GetLen(), offset);
        it->SetBlockHead(tmp);
        offset += it->GetLen();
        bool checkIsLongOverflowIntegerFlag = IsLongOverflowInteger(offset);
        if (checkIsLongOverflowIntegerFlag) {
            PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] The sign block offset is overflow integer.");
            return false;
        }
    }
    return true;
}

SignBlockData SignElf::GenerateProfileSignByte(std::string profileFile, std::string profileSigned)
{
    int64_t profileDataLen = FileUtils::GetFileLen(profileFile);
    if (profileDataLen < 0 || IsLongOverflowShort(profileDataLen)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] generateProfileSignByte profileDataLen error.");
    }
    char isSigned = SignatureBlockTypes::GetProfileBlockTypes(profileSigned);
    return SignBlockData(profileFile, isSigned);
}

bool SignElf::GenerateCodeSignByte(SignerConfig signerConfig, std::map<std::string, std::string> signParams,
                                   std::string inputFile, int blockNum, long binFileLen, SignBlockData** codeSign)
{
    if (signParams.at(ParamConstants::PARAM_SIGN_CODE) == CODESIGN_OFF) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] generateCodeSignByte PARAM_SIGN_CODE error.");
        return false;
    }
    CodeSigning codeSigning(&signerConfig);
    long offset = binFileLen + (long)HwBlockHead::GetElfBlockLen() * blockNum;
    std::string profileContent = signParams.at(ParamConstants::PARAM_PROFILE_JSON_CONTENT);
    std::vector<int8_t> codesignData;
    bool checkGetElfCodeSignBlockFlag = codeSigning.GetElfCodeSignBlock(inputFile, offset,
                                                                        signParams.at(ParamConstants::PARAM_IN_FORM),
                                                                        profileContent, codesignData);
    if (!checkGetElfCodeSignBlockFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "[SignElf] GetElfCodeSignBlock error.");
        return false;
    }
    *codeSign = new SignBlockData(codesignData, CODESIGN_BLOCK_TYPE);
    return true;
}

bool SignElf::WriteSignHeadDataToOutputFile(std::string inputFile, std::string outputFile, int blockNum)
{
    int64_t size = FileUtils::GetFileLen(outputFile) - FileUtils::GetFileLen(inputFile);
    if (IsLongOverflowInteger(size)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR,
                            "[SignElf] writeSignHeadDataToOutputFile isLongOverflowInteger error.");
        return false;
    }
    HwSignHead signHeadData;
    std::vector<int8_t> signHeadByte = signHeadData.GetSignHeadLittleEndian((int)size, blockNum);
    std::ofstream fileOutputStream(outputFile, std::ios::app | std::ios::binary);
    return FileUtils::WriteByteToOutFile(signHeadByte, fileOutputStream);
}

bool SignElf::IsLongOverflowInteger(int64_t num)
{
    return (num - (num & 0xffffffffL)) != 0;
}

bool SignElf::IsLongOverflowShort(int64_t num)
{
    return (num - (num & 0xffffL)) != 0;
}

} // namespace SignatureTools
} // namespace OHOS