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
#include <fstream>
#include <filesystem>
#include "verify_elf.h"
#include "file_utils.h"
#include "hw_sign_head.h"
#include "hw_block_head.h"
#include "hap_verify_v2.h"
#include "verify_code_signature.h"
#include "param_process_util.h"
#include "hash_utils.h"
#include "sign_content_info.h"
#include "signature_block_tags.h"

using namespace OHOS::SignatureTools;

const int8_t VerifyElf::SIGNATURE_BLOCK = 0;
const int8_t VerifyElf::PROFILE_NOSIGNED_BLOCK = 1;
const int8_t VerifyElf::PROFILE_SIGNED_BLOCK = 2;
const int8_t VerifyElf::KEY_ROTATION_BLOCK = 3;
const int8_t VerifyElf::CODESIGNING_BLOCK_TYPE = 3;
const std::string VerifyElf::BIN_FILE_TYPE = "bin";
const std::string VerifyElf::ELF_FILE_TYPE = "elf";

bool VerifyElf::Verify(Options* options)
{
    // check param
    if (options == nullptr) {
        SIGNATURE_TOOLS_LOGE("Param options is null.\n");
        return false;
    }
    if (!CheckParams(options)) {
        SIGNATURE_TOOLS_LOGE("Check params failed!\n");
        return false;
    }
    std::string filePath = options->GetString(Options::IN_FILE);
    if (!CheckSignFile(filePath)) {
        SIGNATURE_TOOLS_LOGE("Check input signature elf false!\n");
        return false;
    }
    // verify elf
    HapVerifyResult verifyResult;
    Pkcs7Context pkcs7Context;
    if (!VerifyElfFile(filePath, verifyResult, options, pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("Verify elf file failed!\n");
        return false;
    }
    // write certificate and p7b file
    HapVerifyV2 hapVerifyV2;
    if (hapVerifyV2.WriteVerifyOutput(pkcs7Context, options) != VERIFY_SUCCESS) {
        SIGNATURE_TOOLS_LOGE("Verify elf WriteElfOutput failed!\n");
        return false;
    }
    return true;
}

bool VerifyElf::VerifyElfFile(const std::string& elfFile, HapVerifyResult& verifyResult,
    Options* options, Pkcs7Context& pkcs7Context)
{
    SignBlockInfo signBlockInfo(false);
    if (!GetSignBlockInfo(elfFile, signBlockInfo, ELF_FILE_TYPE)) {
        SIGNATURE_TOOLS_LOGE("VerifyElfFile GetSignBlockInfo failed!\n");
        return false;
    }
    // verify profile
    std::string profileJson;
    if (!VerifyP7b(signBlockInfo.GetSignBlockMap(), options, pkcs7Context, verifyResult, profileJson)) {
        SIGNATURE_TOOLS_LOGE("VerifyElfFile VerifyProfile failed!\n");
        return false;
    }
    // verify code sign
    if (signBlockInfo.GetSignBlockMap().find(CODESIGNING_BLOCK_TYPE) != signBlockInfo.GetSignBlockMap().end()) {
        SigningBlock codesign = signBlockInfo.GetSignBlockMap().find(CODESIGNING_BLOCK_TYPE)->second;
        if (!VerifyCodeSignature::VerifyElf(elfFile, codesign.GetOffset(), codesign.GetLength(),
            ELF_FILE_TYPE, profileJson)) {
            SIGNATURE_TOOLS_LOGE("ElfFile verify codesign failed!\n");
            return false;
        }
    }
    return true;
}

bool VerifyElf::VerifyP7b(std::unordered_map<signed char, SigningBlock>& signBlockMap,
    Options* options, Pkcs7Context& pkcs7Context, HapVerifyResult& verifyResult, std::string& profileJson)
{
    if (signBlockMap.find(PROFILE_NOSIGNED_BLOCK) != signBlockMap.end()) {
        // verify unsigned profile
        std::vector<int8_t> profileByte = signBlockMap.find(PROFILE_NOSIGNED_BLOCK)->second.GetValue();
        std::string fromByteStr(profileByte.begin(), profileByte.end());
        profileJson = fromByteStr;
        verifyResult.SetProfile(profileByte);
        SIGNATURE_TOOLS_LOGW("profile is not signed.\n");
    } else if (signBlockMap.find(PROFILE_SIGNED_BLOCK) != signBlockMap.end()) {
        // verify signed profile
        SigningBlock profileSign = signBlockMap.find(PROFILE_SIGNED_BLOCK)->second;
        std::vector<int8_t> profileByte = profileSign.GetValue();
        if (!GetRawContent(profileByte, profileJson)) {
            SIGNATURE_TOOLS_LOGE("VerifyElfFile GetProfileContent failed!\n");
            return false;
        }
        HapVerifyV2 hapVerifyV2;
        int32_t resultCode = hapVerifyV2.VerifyElfProfile(profileByte, verifyResult, options, pkcs7Context);
        if (resultCode != VERIFY_SUCCESS) {
            SIGNATURE_TOOLS_LOGE("VerifyElfFile VerifyElfProfile failed!\n");
            return false;
        }
        verifyResult.SetProfile(profileByte);
        SIGNATURE_TOOLS_LOGI("verify profile success.\n");
    } else {
        SIGNATURE_TOOLS_LOGW("can not found profile sign block.\n");
    }
    return true;
}

bool VerifyElf::GetSignBlockInfo(const std::string& file, SignBlockInfo& signBlockInfo,
    const std::string fileType)
{
    // read file
    std::uintmax_t fileSize = std::filesystem::file_size(file);
    std::ifstream fileStream(file, std::ios::binary);
    if (!fileStream.is_open()) {
        SIGNATURE_TOOLS_LOGE("GetSignBlockMap failed to open file\n");
        return false;
    }
    std::vector<int8_t>* fileBytes = new std::vector<int8_t>(fileSize, 0);
    fileStream.read((char*)fileBytes->data(), fileBytes->size());
    fileStream.close();
    // get HwBlockData
    HwBlockData hwBlockData(0, 0);
    if (!GetSignBlockData(*fileBytes, hwBlockData, fileType)) {
        SIGNATURE_TOOLS_LOGE("Verify elf/bin file GetSignBlockData failed!\n");
        delete fileBytes;
        return false;
    }
    // get SignBlockMap
    if (fileType == ELF_FILE_TYPE) {
        GetElfSignBlock(*fileBytes, hwBlockData, signBlockInfo.GetSignBlockMap());
    } else {
        GetBinSignBlock(*fileBytes, hwBlockData, signBlockInfo.GetSignBlockMap());
    }
    // get bin file digest
    if (signBlockInfo.GetNeedGenerateDigest()) {
        std::vector<int8_t> signatrue = signBlockInfo.GetSignBlockMap().find(0)->second.GetValue();
        if (!GetFileDigest(*fileBytes, signatrue, signBlockInfo)) {
            SIGNATURE_TOOLS_LOGE("Verify bin file GetFileDigest failed!\n");
            delete fileBytes;
            return false;
        }
    }
    delete fileBytes;
    return true;
}

bool VerifyElf::GetFileDigest(std::vector<int8_t>& fileBytes, std::vector<int8_t>& signatrue,
    SignBlockInfo& signBlockInfo)
{
    std::string binDigest;
    if (!GetRawContent(signatrue, binDigest)) {
        SIGNATURE_TOOLS_LOGE("VerifyBinDigest GetBinDigest failed!\n");
        return false;
    }
    std::vector<int8_t> rawDigest(binDigest.begin(), binDigest.end());
    signBlockInfo.SetRawDigest(rawDigest);
    GenerateFileDigest(fileBytes, signBlockInfo);
    return true;
}

bool VerifyElf::GenerateFileDigest(std::vector<int8_t>& fileBytes, SignBlockInfo& signBlockInfo)
{
    // get algId
    std::vector<int8_t> rawDigest = signBlockInfo.GetRawDigest();
    std::shared_ptr<ByteBuffer> digBuffer = std::make_shared<ByteBuffer>(rawDigest.size());
    digBuffer->PutData((char*)rawDigest.data(), rawDigest.size());
    digBuffer->Flip();
    int32_t algOffset = 10;
    int16_t algId = 0;
    const char* bufferPtr = digBuffer->GetBufferPtr();
    algId = static_cast<int16_t>(be16toh(*reinterpret_cast<const int16_t*>(bufferPtr + algOffset)));
    // generate digest
    int32_t fileLength = signBlockInfo.GetSignBlockMap().find(0)->second.GetOffset();
    std::string digAlg = HashUtils::GetHashAlgName(algId);
    std::vector<int8_t> generatedDig = HashUtils::GetDigestFromBytes(fileBytes, fileLength, digAlg);
    if (generatedDig.empty()) {
        SIGNATURE_TOOLS_LOGE("GenerateFileDigest failed.\n");
        return false;
    }
    SignContentInfo contentInfo;
    contentInfo.AddContentHashData(0, SignatureBlockTags::HASH_ROOT_4K, algId, generatedDig.size(), generatedDig);
    std::vector<int8_t> dig = contentInfo.GetByteContent();
    if (dig.empty()) {
        SIGNATURE_TOOLS_LOGE("generate file digest is null\n");
        return false;
    }
    signBlockInfo.SetFileDigest(dig);
    return true;
}

bool VerifyElf::GetSignBlockData(std::vector<int8_t>& bytes, HwBlockData& hwBlockData,
    const std::string fileType)
{
    int32_t offset = 0;
    if (!CheckMagicAndVersion(bytes, offset, fileType)) {
        SIGNATURE_TOOLS_LOGE("GetSignBlockData chech magic and version failed!\n");
        return false;
    }
    int32_t intByteLength = 4;
    std::vector<int8_t> blockSizeByte(bytes.begin() + offset, bytes.begin() + offset + intByteLength);
    offset += intByteLength;
    std::vector<int8_t> blockNumByte(bytes.begin() + offset, bytes.begin() + offset + intByteLength);
    if (fileType == BIN_FILE_TYPE) {
        std::reverse(blockSizeByte.begin(), blockSizeByte.end());
        std::reverse(blockNumByte.begin(), blockNumByte.end());
    }
    std::shared_ptr<ByteBuffer> blockNumBf = std::make_shared<ByteBuffer>(blockNumByte.size());
    blockNumBf->PutData((char*)blockNumByte.data(), blockNumByte.size());
    blockNumBf->Flip();
    int32_t blockNum = 0;
    blockNumBf->GetInt32(blockNum);
    std::shared_ptr<ByteBuffer> blockSizeBf = std::make_shared<ByteBuffer>(blockSizeByte.size());
    blockSizeBf->PutData((char*)blockSizeByte.data(), blockSizeByte.size());
    blockSizeBf->Flip();
    int32_t blockSize = 0;
    blockSizeBf->GetInt32(blockSize);
    int32_t blockStart = 0;
    if (fileType == BIN_FILE_TYPE) {
        blockStart = bytes.size() - blockSize;
    } else {
        blockStart = bytes.size() - HwSignHead::SIGN_HEAD_LEN - blockSize;
    }
    hwBlockData.SetBlockNum(blockNum);
    hwBlockData.SetBlockStart(blockStart);
    return true;
}

bool VerifyElf::CheckMagicAndVersion(std::vector<int8_t>& bytes, int32_t& offset, const std::string fileType)
{
    std::string magicStr = (fileType == ELF_FILE_TYPE ? HwSignHead::ELF_MAGIC : HwSignHead::MAGIC);
    offset = bytes.size() - HwSignHead::SIGN_HEAD_LEN;
    std::vector<int8_t> magicByte(bytes.begin() + offset, bytes.begin() + offset + magicStr.size());
    offset += magicStr.size();
    std::vector<int8_t> versionByte(bytes.begin() + offset, bytes.begin() + offset + HwSignHead::VERSION.size());
    offset += HwSignHead::VERSION.size();
    std::vector<int8_t> magicVec(magicStr.begin(), magicStr.end());
    for (int i = 0; i < magicStr.size(); i++) {
        if (magicVec[i] != magicByte[i]) {
            SIGNATURE_TOOLS_LOGE("elf magic verify failed!\n");
            return false;
        }
    }
    std::vector<int8_t> versionVec(HwSignHead::VERSION.begin(), HwSignHead::VERSION.end());
    for (int i = 0; i < HwSignHead::VERSION.size(); i++) {
        if (versionVec[i] != versionByte[i]) {
            SIGNATURE_TOOLS_LOGE("elf sign version verify failed!\n");
            return false;
        }
    }
    return true;
}

void VerifyElf::GetElfSignBlock(std::vector<int8_t>& bytes, HwBlockData& hwBlockData,
    std::unordered_map<signed char, SigningBlock>& signBlockMap)
{
    int32_t headBlockLen = HwSignHead::ELF_BLOCK_LEN;
    int32_t offset = hwBlockData.GetBlockStart();
    for (int i = 0; i < hwBlockData.GetBlockNum(); i++) {
        std::vector<int8_t> blockByte(bytes.begin() + offset, bytes.begin() + offset + headBlockLen);
        std::shared_ptr<ByteBuffer> blockBuffer = std::make_shared<ByteBuffer>(blockByte.size());
        blockBuffer->PutData((char*)blockByte.data(), blockByte.size());
        blockBuffer->Flip();
        signed char type = 0;
        signed char tag = 0;
        int16_t empValue = 0;
        int32_t length = 0;
        int32_t blockOffset = 0;
        blockBuffer->GetByte((int8_t *)&type, sizeof(int8_t));
        blockBuffer->GetByte((int8_t*)&tag, sizeof(int8_t));
        blockBuffer->GetInt16(empValue);
        blockBuffer->GetInt32(length);
        blockBuffer->GetInt32(blockOffset);
        std::vector<int8_t> value(bytes.begin() + hwBlockData.GetBlockStart() + blockOffset,
            bytes.begin() + hwBlockData.GetBlockStart() + blockOffset + length);
        SigningBlock signingBlock(type, value, hwBlockData.GetBlockStart() + blockOffset);
        signBlockMap.insert(std::make_pair(type, signingBlock));
        offset += headBlockLen;
    }
}

void VerifyElf::GetBinSignBlock(std::vector<int8_t>& bytes, HwBlockData& hwBlockData,
    std::unordered_map<signed char, SigningBlock>& signBlockMap)
{
    int32_t headBlockLen = HwSignHead::BIN_BLOCK_LEN;
    int32_t offset = hwBlockData.GetBlockStart();
    for (int i = 0; i < hwBlockData.GetBlockNum(); i++) {
        std::vector<int8_t> blockByte(bytes.begin() + offset, bytes.begin() + offset + headBlockLen);
        std::shared_ptr<ByteBuffer> blockBuffer = std::make_shared<ByteBuffer>(blockByte.size());
        blockBuffer->PutData((char*)blockByte.data(), blockByte.size());
        blockBuffer->Flip();
        signed char type = 0;
        signed char tag = 0;
        int16_t length = 0;
        int32_t blockOffset = 0;
        blockBuffer->GetByte((int8_t*)&type, sizeof(int8_t));
        blockBuffer->GetByte((int8_t*)&tag, sizeof(int8_t));
        const char* bufferPtr = blockBuffer->GetBufferPtr();
        int bfLengthIdx = 2;
        int bfBlockIdx = 4;
        length = static_cast<int16_t>(be16toh(*reinterpret_cast<const int16_t*>(bufferPtr + bfLengthIdx)));
        blockOffset = static_cast<int32_t>(be32toh(*reinterpret_cast<const int32_t*>(bufferPtr + bfBlockIdx)));
        if (length == 0) {
            length = bytes.size() - HwSignHead::SIGN_HEAD_LEN - blockOffset;
        }
        std::vector<int8_t> value(bytes.begin() + blockOffset, bytes.begin() + blockOffset + length);
        SigningBlock signingBlock(type, value, blockOffset);
        signBlockMap.insert(std::make_pair(type, signingBlock));
        offset += headBlockLen;
    }
}

bool VerifyElf::CheckParams(Options* options)
{
    if (options->GetString(Options::OUT_CERT_CHAIN).empty()) {
        SIGNATURE_TOOLS_LOGE("Missing parameter: %{public}s.\n",
            Options::OUT_CERT_CHAIN.c_str());
        return false;
    }
    if (options->GetString(Options::OUT_PROFILE).empty()) {
        SIGNATURE_TOOLS_LOGE("Missing parameter: %{public}s.\n",
            Options::OUT_PROFILE.c_str());
        return false;
    }
    if (options->GetString(Options::PROOF_FILE).empty()) {
        SIGNATURE_TOOLS_LOGW("Missing parameter: %{public}s.\n",
            Options::PROOF_FILE.c_str());
    }
    return true;
}

bool VerifyElf::CheckSignFile(const std::string& signedFile)
{
    if (signedFile.empty()) {
        SIGNATURE_TOOLS_LOGE("Not found verify file path!\n");
        return false;
    }
    if (!FileUtils::IsValidFile(signedFile)) {
        SIGNATURE_TOOLS_LOGE("signedFile is invalid.\n");
        return false;
    }
    return true;
}

bool VerifyElf::GetRawContent(std::vector<int8_t>& contentVec, std::string& rawContent)
{
    PKCS7Data p7Data;
    if (p7Data.Parse(contentVec) < 0) {
        SIGNATURE_TOOLS_LOGE("GetRawContent parse content failed!\n");
        return false;
    }
    if (p7Data.Verify() < 0) {
        SIGNATURE_TOOLS_LOGE("GetRawContent verify content failed!\n");
        return false;
    }
    if (p7Data.GetContent(rawContent) < 0) {
        SIGNATURE_TOOLS_LOGE("GetRawContent GetOriginalRawData failed!\n");
        return false;
    }
    return true;
}