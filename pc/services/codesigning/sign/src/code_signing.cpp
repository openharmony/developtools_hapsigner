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
#include "code_signing.h"

using namespace OHOS::SignatureTools;

const int BUFFER_SIZE = 16 * 1024;
const int FILE_NAME_SIZE = 512;
const int TUPLE_BUF_INDEX = 1;
const int TUPLE_SIZE_INDEX = 2;
const std::vector<std::string> CodeSigning::SUPPORT_FILE_FORM = { "hap", "hsp", "hqf" };
const std::string CodeSigning::HAP_SIGNATURE_ENTRY_NAME = "Hap";
const std::string CodeSigning::ENABLE_SIGN_CODE_VALUE = "1";

CodeSigning::CodeSigning(SignerConfig signConfig)
{
    this->signConfig = signConfig;
}

CodeSigning::CodeSigning()
{
}

bool CodeSigning::getCodeSignBlock(const std::string input, int64_t offset,
    std::string inForm, std::string profileContent, Zip& zip, std::vector<int8_t>& ret)
{
    SIGNATURE_TOOLS_LOGI("Start to sign code.\n");
    if (std::find(SUPPORT_FILE_FORM.begin(), SUPPORT_FILE_FORM.end(), inForm)
            == SUPPORT_FILE_FORM.end()) {
        SIGNATURE_TOOLS_LOGE("file's format is unsupported\n");
        printf("file's format is unsupported\n");
        return false;
    }
    int64_t dataSize = computeDataSize(zip);
    timestamp = getTimestamp();
    int64_t fsvTreeOffset = this->codeSignBlock.computeMerkleTreeOffset(offset);
    std::unique_ptr<FsVerityInfoSegment> fsVerityInfoSegment =
        std::make_unique<FsVerityInfoSegment>((signed char) FsVerityDescriptor::VERSION,
        (signed char) FsVerityGenerator::GetFsVerityHashAlgorithm(),
        (signed char) FsVerityGenerator::GetLog2BlockSize());
    this->codeSignBlock.setFsVerityInfoSegment(*(fsVerityInfoSegment.get()));
    SIGNATURE_TOOLS_LOGI("Sign hap.\n");
    std::string ownerID = HapUtils::getAppIdentifier(profileContent);
    std::ifstream inputStream;
    inputStream.open(input, std::ios::binary);
    if (!inputStream.is_open()) {
        SIGNATURE_TOOLS_LOGE("getCodeSignBlock Failed to open file\n");
        printf("getCodeSignBlock Failed to open file\n");
        inputStream.close();
        return false;
    }
    std::pair<SignInfo, std::vector<int8_t>> hapSignInfoAndMerkleTreeBytesPair;
    if (!signFile(inputStream, dataSize, true, fsvTreeOffset, ownerID,
                  hapSignInfoAndMerkleTreeBytesPair)) {
        SIGNATURE_TOOLS_LOGE("signFile Failed\n");
        printf("signFile Failed\n");
        inputStream.close();
        return false;
    }
    inputStream.close();
    this->codeSignBlock.getHapInfoSegment().setSignInfo(hapSignInfoAndMerkleTreeBytesPair.first);
    this->codeSignBlock.addOneMerkleTree(HAP_SIGNATURE_ENTRY_NAME,
        hapSignInfoAndMerkleTreeBytesPair.second);
    signNativeLibs(input, ownerID);
    updateCodeSignBlock();
    ret = this->codeSignBlock.generateCodeSignBlockByte(fsvTreeOffset);
    SIGNATURE_TOOLS_LOGI("Sign successfully.\n");
    return true;
}

int64_t CodeSigning::computeDataSize(Zip& zip)
{
    int64_t dataSize = 0L;
    for (ZipEntry* entry : zip.GetZipEntries()) {
        ZipEntryHeader* zipEntryHeader = entry->GetZipEntryData()->GetZipEntryHeader();
        if (FileUtils::IsRunnableFile(zipEntryHeader->GetFileName())
            && zipEntryHeader->GetMethod() == Zip::FILE_UNCOMPRESS_METHOD_FLAG) {
            continue;
        }
        // if the first file is not uncompressed abc or so, set dataSize to zero
        if (entry->GetCentralDirectory()->GetOffset() == 0) {
            break;
        }
        // the first entry which is not abc/so/an is found, return its data offset
        dataSize = entry->GetCentralDirectory()->GetOffset() + ZipEntryHeader::HEADER_LENGTH
            + zipEntryHeader->GetFileNameLength() + zipEntryHeader->GetExtraLength();
        break;
    }
    if ((dataSize % CodeSignBlock::PAGE_SIZE_4K) != 0) {
    }
    return dataSize;
}

int64_t CodeSigning::getTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto now_seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
    return now_seconds.time_since_epoch().count();
}

bool CodeSigning::signFile(std::istream& inputStream, int64_t fileSize, bool storeTree,
    int64_t fsvTreeOffset, std::string ownerID, std::pair<SignInfo, std::vector<int8_t>>& ret)
{
    std::unique_ptr<FsVerityGenerator> fsVerityGenerator =
        std::make_unique<FsVerityGenerator>();
    fsVerityGenerator->GenerateFsVerityDigest(inputStream, fileSize, fsvTreeOffset);
    std::vector<int8_t> fsVerityDigest = fsVerityGenerator->GetFsVerityDigest();
    std::vector<int8_t> signature;
    if (!generateSignature(fsVerityDigest, ownerID, signature)) {
        SIGNATURE_TOOLS_LOGE("generateSignature Fail\n");
        printf("generateSignature Fail\n");
        return false;
    }
    int flags = 0;
    if (storeTree) {
        flags = SignInfo::FLAG_MERKLE_TREE_INCLUDED;
    }
    SignInfo signInfo(fsVerityGenerator->GetSaltSize(), flags, fileSize,
        fsVerityGenerator->GetSalt(), signature);
    // if store merkle tree in sign info
    if (storeTree) {
        int merkleTreeSize = fsVerityGenerator->GetTreeBytes().empty() ? 0
            : fsVerityGenerator->GetTreeBytes().size();
        MerkleTreeExtension* merkleTreeExtension = new MerkleTreeExtension(merkleTreeSize,
            fsvTreeOffset, fsVerityGenerator->GetRootHash());
        signInfo.addExtension(merkleTreeExtension);
    }
    ret = std::make_pair(signInfo, fsVerityGenerator->GetTreeBytes());
    return true;
}

bool CodeSigning::signNativeLibs(std::string input, std::string ownerID)
{
    // 'an' libs are always signed
    extractedNativeLibSuffixs.push_back(NATIVE_LIB_AN_SUFFIX);
    // 'so' libs are always signed
    extractedNativeLibSuffixs.push_back(NATIVE_LIB_SO_SUFFIX);
    // sign native files
    std::vector<std::tuple<std::string, std::stringbuf, uLong>> entryNames =
        GetNativeEntriesFromHap(input);
    if (entryNames.empty()) {
        SIGNATURE_TOOLS_LOGI("No native libs.\n");
        return true;
    }
    std::vector<std::pair<std::string, SignInfo>> nativeLibInfoList;
    if (!SignFilesFromJar(entryNames, input, ownerID, nativeLibInfoList)) {
        SIGNATURE_TOOLS_LOGE("SignFilesFromJar Fail in signNativeLibs\n");
        printf("SignFilesFromJar Fail in signNativeLibs\n");
        return false;
    }
    // update SoInfoSegment in CodeSignBlock
    this->codeSignBlock.getSoInfoSegment().setSoInfoList(nativeLibInfoList);
    return true;
}

void CodeSigning::updateCodeSignBlock()
{
    // construct segment header list
    this->codeSignBlock.setSegmentHeaders();
    // Compute and set segment number
    this->codeSignBlock.setSegmentNum();
    // update code sign block header flag
    this->codeSignBlock.setCodeSignBlockFlag();
    // compute segment offset
    this->codeSignBlock.computeSegmentOffset();
}

std::vector<std::tuple<std::string, std::stringbuf, uLong>> CodeSigning::GetNativeEntriesFromHap(
    std::string& packageName)
{
    std::vector<std::tuple<std::string, std::stringbuf, uLong>> result;
    unzFile zFile = unzOpen(packageName.c_str());
    if (zFile == NULL) {
        SIGNATURE_TOOLS_LOGE("unzOpen failed\n");
        return std::vector<std::tuple<std::string, std::stringbuf, uLong>>();
    }
    // get zipFile all paramets
    unz_global_info zGlobalInfo;
    if (unzGetGlobalInfo(zFile, &zGlobalInfo) != UNZ_OK) {
        SIGNATURE_TOOLS_LOGE("unzGetGlobalInfo failed\n");
        unzClose(zFile);
        return std::vector<std::tuple<std::string, std::stringbuf, uLong>>();
    }
    // search each file
    char* szReadBuffer = new char[BUFFER_SIZE];
    if (!handleZipGlobalInfo(zFile, zGlobalInfo, szReadBuffer, result)) {
        return std::vector<std::tuple<std::string, std::stringbuf, uLong>>();
    }
    unzCloseCurrentFile(zFile);
    unzGoToNextFile(zFile);
    delete[] szReadBuffer;
    return result;
}

bool CodeSigning::handleZipGlobalInfo(unzFile& zFile, unz_global_info& zGlobalInfo,
    char* szReadBuffer, std::vector<std::tuple<std::string, std::stringbuf, uLong>>& result)
{
    unz_file_info zFileInfo;
    char fileName[FILE_NAME_SIZE];
    char fileNameZeroBuf[FILE_NAME_SIZE] = { 0 };
    char bzReadZeroBuf[BUFFER_SIZE] = { 0 };
    SIGNATURE_TOOLS_LOGI("zGlobalInfo.number_entry = %lu\n", zGlobalInfo.number_entry);
    for (uLong i = 0; i < zGlobalInfo.number_entry; ++i) {
        memcpy_s(fileName, FILE_NAME_SIZE, fileNameZeroBuf, FILE_NAME_SIZE);
        size_t nameLen = 0;
        if (!checkUnzParam(zFile, zFileInfo, fileName, &nameLen)) {
            return false;
        }
        if (!checkFileName(zFile, fileName, &nameLen)) {
            continue;
        }
        long fileLength = zFileInfo.uncompressed_size;
        int readFileSize = 0;
        int nReadFileSize;
        std::stringbuf sb;
        do {
            nReadFileSize = 0;
            memcpy_s(szReadBuffer, BUFFER_SIZE, bzReadZeroBuf, BUFFER_SIZE);
            nReadFileSize = unzReadCurrentFile(zFile, szReadBuffer, BUFFER_SIZE);
            if (nReadFileSize > 0) {
                sb.sputn(szReadBuffer, nReadFileSize);
            }
            fileLength -= nReadFileSize;
            readFileSize += nReadFileSize;
        } while (fileLength > 0 && nReadFileSize > 0);
        if (fileLength) {
            SIGNATURE_TOOLS_LOGE("stream is incomplete\n");
            unzCloseCurrentFile(zFile);
            unzGoToNextFile(zFile);
            delete[] szReadBuffer;
            return false;
        }
        std::string str_tmp = sb.str();
        std::vector<char> vec(str_tmp.begin(), str_tmp.end());
        result.push_back(std::make_tuple(fileName, std::move(sb), readFileSize));
        unzCloseCurrentFile(zFile);
        unzGoToNextFile(zFile);
    }
    return true;
}

bool CodeSigning::checkUnzParam(unzFile& zFile, unz_file_info& zFileInfo,
    char* fileName, size_t* nameLen)
{
    if (UNZ_OK != unzGetCurrentFileInfo(zFile, &zFileInfo, fileName,
            FILE_NAME_SIZE, NULL, 0, NULL, 0)) {
        SIGNATURE_TOOLS_LOGE("unzGetCurrentFileInfo failed!\n");
        return false;
    }
    SIGNATURE_TOOLS_LOGI("Open zipFile filename is : %{public}s\n", fileName);
    if ((*nameLen = strlen(fileName)) == 0U) {
        SIGNATURE_TOOLS_LOGE("fileName is null\n");
        return false;
    }
    if (UNZ_OK != unzOpenCurrentFile(zFile)) {
        SIGNATURE_TOOLS_LOGE("Open zipFile filename is : %{public}s failed.\n", fileName);
        return false;
    }
    return true;
}

bool CodeSigning::checkFileName(unzFile& zFile, char* fileName, size_t* nameLen)
{
    if (fileName[*nameLen - 1] == '/') {
        SIGNATURE_TOOLS_LOGI("It is dictionary.\n");
        unzCloseCurrentFile(zFile);
        unzGoToNextFile(zFile);
        return false;
    }
    std::string str(fileName);
    if (!isNativeFile(str)) {
        SIGNATURE_TOOLS_LOGI("Suffix mismatched.\n");
        unzCloseCurrentFile(zFile);
        unzGoToNextFile(zFile);
        return false;
    }
    return true;
}

std::string CodeSigning::splitFileName(const std::string& path)
{
    size_t found = path.find_last_of("/");
    if (found == std::string::npos) {
        found = 0;
    } else {
        ++found;
    }
    return path.substr(found);
}

bool CodeSigning::isNativeFile(std::string& input)
{
    size_t dotPos = input.rfind('.');
    if (dotPos == std::string::npos) {
        return false;
    }
    std::string suffix = input.substr(dotPos + 1);
    if (suffix == "an" || suffix == "so") {
        return true;
    } else {
        return false;
    }
}

bool CodeSigning::SignFilesFromJar(std::vector<std::tuple<std::string,
    std::stringbuf, uLong>>&entryNames, std::string& packageName, const std::string& ownerID,
    std::vector<std::pair<std::string, SignInfo>>& ret)
{
    for (int i = 0; i < static_cast<int>(entryNames.size()); i++) {
        std::istream input(&(std::get<TUPLE_BUF_INDEX>(entryNames[i])));
        std::pair<SignInfo, std::vector<int8_t>> pairSignInfoAndMerkleTreeBytes;
        if (!signFile(input, std::get<TUPLE_SIZE_INDEX>(entryNames[i]), false, 0, ownerID,
            pairSignInfoAndMerkleTreeBytes)) {
            SIGNATURE_TOOLS_LOGE("signFile Failed in SignFilesFromJar\n");
            printf("signFile Failed in SignFilesFromJar\n");
            std::ifstream* inputFile = (std::ifstream*)(&input);
            inputFile->close();
            return false;
        }
        std::ifstream* inputFile = (std::ifstream*)(&input);
        inputFile->close();
        ret.push_back(std::make_pair(std::get<0>(entryNames[i]), pairSignInfoAndMerkleTreeBytes.first));
    }
    return true;
}

bool CodeSigning::generateSignature(std::vector<int8_t>& signedData, const std::string& ownerID,
    std::vector<int8_t>& ret)
{
    if (signConfig.GetSigner() != nullptr) {
        if (signConfig.GetCertificates() == nullptr) {
            SIGNATURE_TOOLS_LOGW("No certificates configured for sign.\n");
            printf("generateSignature No certificates configured for sign.\n");
            return false;
        }
    }
    std::unique_ptr<BCSignedDataGenerator> bcSignedDataGenerator =
        std::make_unique<BCSignedDataGenerator>();
    if (!ownerID.empty()) {
        SIGNATURE_TOOLS_LOGW("generate signature get owner id not null.\n");
        bcSignedDataGenerator->SetOwnerId(ownerID);
    }
    std::string signed_data(signedData.begin(), signedData.end());
    std::string ret_str;
    if (signedData.empty()) {
        SIGNATURE_TOOLS_LOGW("generateSignature Verity digest is null\n");
        printf("generateSignature Verity digest is null\n");
        return false;
    }
    if (bcSignedDataGenerator->GenerateSignedData(signed_data, &signConfig, ret_str)) {
        SIGNATURE_TOOLS_LOGW("failed to GenerateSignedData unsigned data!\n");
        printf("failed to GenerateSignedData unsigned data!\n");
        return false;
    }
    ret = std::vector<int8_t>(ret_str.begin(), ret_str.end());
    return true;
}