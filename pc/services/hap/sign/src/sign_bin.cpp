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
#include "sign_bin.h"
#include "param_constants.h"
#include "file_utils.h"
#include "param_process_util.h"
#include "hw_block_head.h"
#include "signature_block_types.h"
#include "signature_block_tags.h"
#include "hash_utils.h"
#include "sign_content_info.h"
#include "hw_sign_head.h"
#include "bc_pkcs7_generator.h"

using namespace OHOS::SignatureTools;

bool SignBin::Sign(SignerConfig& signerConfig, const std::map<std::string, std::string> &signParams) {
    /* 1. Make block head, write to output file. */
    std::string signCode = signParams.at(ParamConstants::PARAM_SIGN_CODE);
    if (ParamConstants::ENABLE_SIGN_CODE == signCode) 
    {
        SIGNATURE_TOOLS_LOGW("can not sign bin with codesign.\n");
    }
    std::string inputFile = signParams.at(ParamConstants::PARAM_BASIC_INPUT_FILE);
    std::string outputFile = signParams.at(ParamConstants::PARAM_BASIC_OUTPUT_FILE);
    std::string profileFile = signParams.at(ParamConstants::PARAM_BASIC_PROFILE);
    std::string profileSigned = signParams.at(ParamConstants::PARAM_BASIC_PROFILE_SIGNED);

    // ��ԭbin�ļ������ݣ�������Ϊͷ,�Լ�p7b�ļ�������,д��Ŀ���ļ�
    if (!WriteBlockDataToFile(inputFile, outputFile, profileFile, profileSigned)) {
        SIGNATURE_TOOLS_LOGE("The block head data made failed.\n");
        FileUtils::DelDir(outputFile);
        return false;
    }

    /* 2. Make sign data, and append write to output file */
    std::string signAlg = signParams.at(ParamConstants::PARAM_BASIC_SIGANTURE_ALG);
    if (!WriteSignDataToOutputFile(signerConfig, outputFile, signAlg)) {
        SIGNATURE_TOOLS_LOGE("The sign data made failed.\n");
        FileUtils::DelDir(outputFile);
        return false;
    }

    /* 3. Make sign head data, and write to output file */
    if (!WriteSignHeadDataToOutputFile(inputFile, outputFile)) {
        SIGNATURE_TOOLS_LOGE("The sign head data made failed.\n");
        FileUtils::DelDir(outputFile);
        return false;
    }

    return true;
}

bool SignBin::WriteBlockDataToFile(const std::string& inputFile, const std::string& outputFile,
    const std::string& profileFile, const std::string& profileSigned) {
    // ���ļ������ļ����ڷ����ļ��ĳ��ȣ����򷵻�-1
    int64_t binFileLen = FileUtils::GetFileLen(inputFile);
    int64_t profileDataLen = FileUtils::GetFileLen(profileFile);

    // У�� binFileLen != -1 ���� profileDataLen ��= -1 ���� profileDataLen ��ֵ������ short
    if (!CheckBinAndProfileLengthIsValid(binFileLen, profileDataLen)) {
        // SIGNATURE_TOOLS_LOGE("file length is invalid, binFileLen: %{public}lld, profileDataLen: %{public}lld\n", 
        //     binFileLen, profileDataLen);
        return false;
    }

    // ԭbin�ļ��ĳ���+2����Ϊͷ�ĳ���
    int64_t offset = binFileLen + HwBlockHead::GetBlockLen() + HwBlockHead::GetBlockLen();
    if (IsLongOverflowInteger(offset)) {
        SIGNATURE_TOOLS_LOGE("The profile block head offset is overflow integer range.\n");
        return false;
    }
    char isSigned = SignatureBlockTypes::GetProfileBlockTypes(profileSigned);

    // 8���ֽ�д���ֽ�����             ǩ��������: PROFILE_SIGNED_BLOCK=2(��ǩ����profile),ǩ�������ǩ: DEFAULT=0,
    std::string proBlockByte =
        HwBlockHead::GetBlockHead(isSigned, SignatureBlockTags::DEFAULT, (short)profileDataLen, (int)offset);

    // ԭbin�ļ��ĳ���+2����Ϊͷ�ĳ���+p7b�ļ��ĳ���
    offset += profileDataLen;
    if (IsLongOverflowInteger(offset)) {
        SIGNATURE_TOOLS_LOGE("The sign block head offset is overflow integer range.\n");
        return false;
    }

    // 8���ֽ�д���ֽ�����                     ǩ��������: SIGNATURE_BLOCK=0(hapǩ����),ǩ�������ǩ:DEFAULT=0
    std::string signBlockByte = HwBlockHead::GetBlockHead(
        SignatureBlockTypes::SIGNATURE_BLOCK, SignatureBlockTags::DEFAULT, (short)0, (int)offset);

    // ��ԭbin�ļ���profileBlock,signBlock,p7b�ļ�,д��Ŀ���ļ�
    return WriteSignedBin(inputFile, proBlockByte, signBlockByte, profileFile, outputFile);
}

std::vector<int8_t> SignBin::GenerateFileDigest(const std::string& outputFile, 
    const std::string& signAlg) {
    // ����ǩ���㷨���ƻ�ȡǩ���㷨����
    SignatureAlgorithmClass signatureAlgorithmClass;
    if (!ParamProcessUtil::getSignatureAlgorithm(signAlg, signatureAlgorithmClass)) {
        SIGNATURE_TOOLS_LOGE("[SignHap] get Signature Algorithm failed");
        return std::vector<int8_t>();
    }
    // ����ǩ���㷨�����ȡժҪ�㷨����
    std::string alg = signatureAlgorithmClass.contentDigestAlgorithm.GetDigestAlgorithm();

    // [Ŀ���ļ�ժҪ] ��Ŀ���ļ���ÿ��4k��С��ȡ��Ȼ��Զ�ȡ��ÿ���ֽڿ����ժҪ������ٶ�����ժҪ����һ��ժҪ����
    std::vector<int8_t> data = HashUtils::GetFileDigest(outputFile, alg);
    if (data.empty()) {
        SIGNATURE_TOOLS_LOGE("GetFileDigest failed.\n");
        return std::vector<int8_t>();
    }

    std::vector<int8_t> outputChunk;
    SignContentInfo contentInfo;
    contentInfo.AddContentHashData(0, SignatureBlockTags::HASH_ROOT_4K, HashUtils::GetHashAlgsId(alg),
        data.size(), data);

    // 1.4���ֽ�: �Ѱ汾���ַ���"1000",д���ֽ�����
    // 2.2���ֽ�: ��[ժҪͷ�ĳ���8+Ŀ���ļ�ժҪ�ĳ���],д���ֽ�����
    // 3.2���ֽ�: ǩ���ӿ�ĸ���1,д���ֽ�����
    // 4.1���ֽ�: ǩ���ӿ������0,д���ֽ�����
    // 5.1���ֽ�: ���λ����Merkletree �ĸ��ڵ� 0x88,д���ֽ�����
    // 6.2���ֽ�: �㷨id,д���ֽ�����
    // 7.4���ֽ�: Ŀ���ļ�ժҪ�ĳ���,д���ֽ�����
    // 8.32���ֽ�: ��Ŀ���ļ�ժҪ����,д���ֽ�����
    std::vector<int8_t> dig = contentInfo.GetByteContent();
    if (dig.empty()) {
        SIGNATURE_TOOLS_LOGE("generate file digest is null\n");
        return std::vector<int8_t>();
    }
    return dig;
}

bool SignBin::WriteSignDataToOutputFile(SignerConfig& SignerConfig, const std::string& outputFile,
    const std::string& signAlg) {
    // ����ժҪ����
    std::vector<int8_t> dig = GenerateFileDigest(outputFile, signAlg);
    if (dig.empty()) {
        SIGNATURE_TOOLS_LOGE("generateSignature Verity digest is null\n");
        return false;
    }

    // ����ǩ������
    std::string ret_str;
    std::string signed_data(dig.begin(), dig.end());
    std::unique_ptr<Pkcs7Generator> generator = std::make_unique<BCPkcs7Generator>();
    if (generator->GenerateSignedData(signed_data, &SignerConfig, ret_str)) {
        SIGNATURE_TOOLS_LOGE("failed to GenerateSignedData!\n");
        return false;
    }

    // ǩ������׷��д��Ŀ���ļ�
    bool writeByteToOutFile = FileUtils::AppendWriteByteToFile(ret_str, outputFile);
    if (!writeByteToOutFile) {
        SIGNATURE_TOOLS_LOGE("write signedData to outputFile failed!\n");
        return false;
    }
    return true;
}

bool SignBin::WriteSignHeadDataToOutputFile(const std::string &inputFile, const std::string &outputFile) {
    int64_t size = FileUtils::GetFileLen(outputFile) - FileUtils::GetFileLen(inputFile) + HwSignHead::SIGN_HEAD_LEN;
    if (IsLongOverflowInteger(size)) {
        SIGNATURE_TOOLS_LOGE("File size is Overflow integer range!\n");
        return false;
    }

    HwSignHead signHeadData;
    // 1.16���ֽڣ��ַ��� ��hw signed app   ��
    // 2.4���ֽڣ��汾���ַ���"1000"
    // 3.4���ֽڣ�Ŀ���ļ��ĳ���-ԭ�ļ��ĳ���+��Ϊǩ��ͷ�ĳ���32
    // 4.4���ֽڣ��ӿ�ĸ���
    // 5.4���ֽڣ�reserve���������
    std::vector<int8_t> signHeadByte = signHeadData.GetSignHead(size);
    if (signHeadByte.empty()) {
        SIGNATURE_TOOLS_LOGE("Failed to get sign head data!\n");
        return false;
    }

    bool writeByteToOutFile =
        FileUtils::AppendWriteByteToFile(std::string(signHeadByte.begin(), signHeadByte.end()), outputFile);
    if (!writeByteToOutFile) {
        SIGNATURE_TOOLS_LOGE("Failed to WriteByteToOutFile!\n");
        return false;
    }

    return true;
}

bool SignBin::CheckBinAndProfileLengthIsValid(int64_t binFileLen, int64_t profileDataLen) {
    return binFileLen != -1 && profileDataLen != -1 && !IsLongOverflowShort(profileDataLen);
}

bool SignBin::IsLongOverflowInteger(int64_t num) { 
    return (num - (num & 0xffffffffL)) != 0; 
}

bool SignBin::IsLongOverflowShort(int64_t num) { 
    return (num - (num & 0xffff)) != 0; 
}

bool SignBin::WriteSignedBin(const std::string &inputFile, const std::string& proBlockByte,
    const std::string& signBlockByte, const std::string& profileFile,
    const std::string& outputFile) {
    // 1. write the input file to the output file.
    if (!FileUtils::WriteInputToOutPut(inputFile, outputFile)) {
        SIGNATURE_TOOLS_LOGE("Failed to write information of input file: %{public}s to output file: %{public}s",
                             inputFile.c_str(), outputFile.c_str());
        return false;
    }

    // 2. append write profile block head to the output file.
    if (!FileUtils::AppendWriteByteToFile(proBlockByte, outputFile)) {
        SIGNATURE_TOOLS_LOGE("Failed to append write proBlockByte to output file: %{public}s", outputFile.c_str());
        return false;
    }

    // 3. append write sign block head to the output file.
    if (!FileUtils::AppendWriteByteToFile(signBlockByte, outputFile)) {
        SIGNATURE_TOOLS_LOGE("Failed to append write binBlockByte to output file: %{public}s", outputFile.c_str());
        return false;
    }

    // 4. write profile src file to the output file.
    if (!FileUtils::AppendWriteFileToFile(profileFile, outputFile)) {
        SIGNATURE_TOOLS_LOGE("Failed to write profile file %{public}s", profileFile.c_str());
        return false;
    }
    return true;
}