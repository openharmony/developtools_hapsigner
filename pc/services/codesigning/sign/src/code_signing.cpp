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
#include "code_signing.h"
#include "elf_sign_block.h"
#include "fs_verity_descriptor.h"
#include "fs_verity_descriptor_with_sign.h"

namespace OHOS {
namespace SignatureTools {
const int BUFFER_SIZE = 16 * 1024;
const int FILE_NAME_SIZE = 512;
const int TUPLE_BUF_INDEX = 1;
const int TUPLE_SIZE_INDEX = 2;
const std::vector<std::string> CodeSigning::SUPPORT_FILE_FORM = { "hap", "hsp", "hqf" };
const std::string CodeSigning::HAP_SIGNATURE_ENTRY_NAME = "Hap";
const std::string CodeSigning::ENABLE_SIGN_CODE_VALUE = "1";
const std::string CodeSigning::SUPPORT_BIN_FILE_FORM = "elf";

const FsVerityHashAlgorithm FS_SHA256(1, "SHA-256", 256 / 8);
const FsVerityHashAlgorithm FS_SHA512(2, "SHA-512", 512 / 8);
const int8_t LOG_2_OF_FSVERITY_HASH_PAGE_SIZE = 12;

CodeSigning::CodeSigning(SignerConfig* signConfig)
{
    this->signConfig = signConfig;
}

CodeSigning::CodeSigning()
{
}

bool CodeSigning::GetCodeSignBlock(const std::string input, int64_t offset,
                                   std::string inForm, std::string profileContent, ZipSigner& zip, std::vector<int8_t>& ret)
{
    SIGNATURE_TOOLS_LOGI("Start to sign code.\n");
    bool formatFlag = std::find(SUPPORT_FILE_FORM.begin(), SUPPORT_FILE_FORM.end(), inForm)
        == SUPPORT_FILE_FORM.end();
    if (formatFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "file's format is unsupported");
        return false;
    }
    int64_t dataSize = ComputeDataSize(zip);
    timestamp = GetTimestamp();
    int64_t fsvTreeOffset = this->codeSignBlock.ComputeMerkleTreeOffset(offset);
    std::unique_ptr<FsVerityInfoSegment> fsVerityInfoSegment =
        std::make_unique<FsVerityInfoSegment>((signed char)FsVerityDescriptor::VERSION,
                                              (signed char)FsVerityGenerator::GetFsVerityHashAlgorithm(),
                                              (signed char)FsVerityGenerator::GetLog2BlockSize());
    this->codeSignBlock.SetFsVerityInfoSegment(*(fsVerityInfoSegment.get()));
    SIGNATURE_TOOLS_LOGI("Sign hap.\n");
    std::string ownerID = HapUtils::GetAppIdentifier(profileContent);
    std::ifstream inputStream;
    inputStream.open(input, std::ios::binary);
    if (!inputStream.is_open()) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "getCodeSignBlock Failed to open file");
        inputStream.close();
        return false;
    }
    std::pair<SignInfo, std::vector<int8_t>> hapSignInfoAndMerkleTreeBytesPair;
    bool signFileFlag = SignFile(inputStream, dataSize, true, fsvTreeOffset, ownerID,
                                 hapSignInfoAndMerkleTreeBytesPair);
    if (!signFileFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "signFile Failed");
        inputStream.close();
        return false;
    }
    inputStream.close();
    this->codeSignBlock.GetHapInfoSegment().SetSignInfo(hapSignInfoAndMerkleTreeBytesPair.first);
    this->codeSignBlock.AddOneMerkleTree(HAP_SIGNATURE_ENTRY_NAME,
                                         hapSignInfoAndMerkleTreeBytesPair.second);
    SignNativeLibs(input, ownerID);
    UpdateCodeSignBlock();
    ret = this->codeSignBlock.GenerateCodeSignBlockByte(fsvTreeOffset);
    SIGNATURE_TOOLS_LOGI("Sign successfully.\n");
    return true;
}

int64_t CodeSigning::ComputeDataSize(ZipSigner& zip)
{
    int64_t dataSize = 0L;
    for (ZipEntry* entry : zip.GetZipEntries()) {
        ZipEntryHeader* zipEntryHeader = entry->GetZipEntryData()->GetZipEntryHeader();
        bool runnableFileFlag = FileUtils::IsRunnableFile(zipEntryHeader->GetFileName())
            && zipEntryHeader->GetMethod() == ZipSigner::FILE_UNCOMPRESS_METHOD_FLAG;
        if (runnableFileFlag) {
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

int64_t CodeSigning::GetTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto now_seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
    return now_seconds.time_since_epoch().count();
}

bool CodeSigning::SignFile(std::istream& inputStream, int64_t fileSize, bool storeTree,
                           int64_t fsvTreeOffset, std::string ownerID, std::pair<SignInfo, std::vector<int8_t>>& ret)
{
    std::unique_ptr<FsVerityGenerator> fsVerityGenerator =
        std::make_unique<FsVerityGenerator>();
    fsVerityGenerator->GenerateFsVerityDigest(inputStream, fileSize, fsvTreeOffset);
    std::vector<int8_t> fsVerityDigest = fsVerityGenerator->GetFsVerityDigest();
    std::vector<int8_t> signature;
    bool generateSignatureFlag = GenerateSignature(fsVerityDigest, ownerID, signature);
    if (!generateSignatureFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "generateSignature Fail");
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
                                                                           fsvTreeOffset,
                                                                           fsVerityGenerator->GetRootHash());
        signInfo.AddExtension(merkleTreeExtension);
    }
    ret = std::make_pair(signInfo, fsVerityGenerator->GetTreeBytes());
    return true;
}

bool CodeSigning::GetElfCodeSignBlock(std::string input, int64_t offset,
                                      std::string inForm, std::string profileContent,
                                      std::vector<int8_t>& codesignData)
{
    SIGNATURE_TOOLS_LOGI("Start to sign elf code.\n");
    if (CodeSigning::SUPPORT_BIN_FILE_FORM != inForm) {
        SIGNATURE_TOOLS_LOGI("[SignElf] file's format is unsupported\n");
        return false;
    }
    int paddingSize = ElfSignBlock::ComputeMerkleTreePaddingLength(offset);
    int64_t fsvTreeOffset = offset + FsVerityDescriptorWithSign::INTEGER_BYTES * 2 + paddingSize;
    std::ifstream inputstream(input, std::ios::binary | std::ios::ate);
    if (!inputstream.is_open()) {
        SIGNATURE_TOOLS_LOGI("[SignElf] input file open is fail\n");
        return false;
    }
    std::streamsize fileSize = inputstream.tellg();
    inputstream.seekg(0, std::ios::beg);
    std::shared_ptr<FsVerityGenerator> fsVerityGenerator = std::make_shared<FsVerityGenerator>();
    fsVerityGenerator->GenerateFsVerityDigest(inputstream, fileSize, fsvTreeOffset);
    std::vector<int8_t> fsVerityDigest = fsVerityGenerator->GetFsVerityDigest();
    std::string ownerID = profileContent.empty() ? "DEBUF_LIB_ID" : HapUtils::GetAppIdentifier(profileContent);
    std::vector<int8_t> signature;
    bool generateSignatureFlag = GenerateSignature(fsVerityDigest, ownerID, signature);
    if (!generateSignatureFlag) {
        SIGNATURE_TOOLS_LOGI("[SignElf] generateSignature fail\n");
        return false;
    }

    FsVerityDescriptor::Builder fsdbuilder = (new FsVerityDescriptor::Builder())->SetFileSize(fileSize)
        .SetHashAlgorithm(FS_SHA256.GetId())
        .SetLog2BlockSize(LOG_2_OF_FSVERITY_HASH_PAGE_SIZE)
        .SetSaltSize(fsVerityGenerator->GetSaltSize())
        .SetSignSize(signature.size())
        .SetFileSize(fileSize)
        .SetSalt(fsVerityGenerator->Getsalt())
        .SetRawRootHash(fsVerityGenerator->GetRootHash())
        .SetFlags(FsVerityDescriptor::FLAG_STORE_MERKLE_TREE_OFFSET)
        .SetMerkleTreeOffset(fsvTreeOffset)
        .SetCsVersion(FsVerityDescriptor::CODE_SIGN_VERSION);

    FsVerityDescriptorWithSign fsVerityDescriptorWithSign =
        FsVerityDescriptorWithSign(FsVerityDescriptor(fsdbuilder), signature);
    std::vector<int8_t> treeBytes = fsVerityGenerator->GetTreeBytes();
    ElfSignBlock signBlock = ElfSignBlock(paddingSize, treeBytes, fsVerityDescriptorWithSign);
    codesignData = signBlock.ToByteArray();
    return true;
}

bool CodeSigning::SignNativeLibs(std::string input, std::string ownerID)
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
    bool signFilesFromJarFlag = SignFilesFromJar(entryNames, input, ownerID, nativeLibInfoList);
    if (!signFilesFromJarFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "SignFilesFromJar Fail in signNativeLibs");
        return false;
    }
    // update SoInfoSegment in CodeSignBlock
    this->codeSignBlock.GetSoInfoSegment().SetSoInfoList(nativeLibInfoList);
    return true;
}

void CodeSigning::UpdateCodeSignBlock()
{
    // construct segment header list
    this->codeSignBlock.SetSegmentHeaders();
    // Compute and set segment number
    this->codeSignBlock.SetSegmentNum();
    // update code sign block header flag
    this->codeSignBlock.SetCodeSignBlockFlag();
    // compute segment offset
    this->codeSignBlock.ComputeSegmentOffset();
}

std::vector<std::tuple<std::string, std::stringbuf, uLong>> CodeSigning::GetNativeEntriesFromHap(
    std::string& packageName)
{
    std::vector<std::tuple<std::string, std::stringbuf, uLong>> result;
    unzFile zFile = unzOpen(packageName.c_str());
    if (zFile == NULL) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "unzOpen failed");
        return std::vector<std::tuple<std::string, std::stringbuf, uLong>>();
    }
    // get zipFile all paramets
    unz_global_info zGlobalInfo;
    int getRet = unzGetGlobalInfo(zFile, &zGlobalInfo);
    if (getRet != UNZ_OK) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "unzGetGlobalInfo failed");
        unzClose(zFile);
        return std::vector<std::tuple<std::string, std::stringbuf, uLong>>();
    }
    // search each file
    bool handleFlag = HandleZipGlobalInfo(zFile, zGlobalInfo, result);
    if (!handleFlag) {
        unzClose(zFile);
        return std::vector<std::tuple<std::string, std::stringbuf, uLong>>();
    }
    unzCloseCurrentFile(zFile);
    unzGoToNextFile(zFile);
    unzClose(zFile);
    return result;
}

bool CodeSigning::HandleZipGlobalInfo(unzFile& zFile, unz_global_info& zGlobalInfo,
                                      std::vector<std::tuple<std::string, std::stringbuf, uLong>>& result)
{
    char szReadBuffer[BUFFER_SIZE] = { 0 };
    unz_file_info zFileInfo;
    char fileName[FILE_NAME_SIZE];
    char fileNameZeroBuf[FILE_NAME_SIZE] = { 0 };
    SIGNATURE_TOOLS_LOGI("zGlobalInfo.number_entry = %lu\n", zGlobalInfo.number_entry);
    for (uLong i = 0; i < zGlobalInfo.number_entry; ++i) {
        if (memcpy_s(fileName, FILE_NAME_SIZE, fileNameZeroBuf, FILE_NAME_SIZE) != 0)
            return false;
        size_t nameLen = 0;
        if (!CheckUnzParam(zFile, zFileInfo, fileName, &nameLen)) {
            return false;
        }
        if (!CheckFileName(zFile, fileName, &nameLen)) {
            continue;
        }
        long fileLength = zFileInfo.uncompressed_size;
        int readFileSize = 0;
        int nReadFileSize;
        std::stringbuf sb;
        do {
            nReadFileSize = 0;
            memset_s(szReadBuffer, BUFFER_SIZE, 0, BUFFER_SIZE);
            nReadFileSize = unzReadCurrentFile(zFile, szReadBuffer, BUFFER_SIZE);
            if (nReadFileSize > 0) {
                sb.sputn(szReadBuffer, nReadFileSize);
            }
            fileLength -= nReadFileSize;
            readFileSize += nReadFileSize;
        } while (fileLength > 0 && nReadFileSize > 0);
        if (fileLength) {
            PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "stream is incomplete");
            unzCloseCurrentFile(zFile);
            unzGoToNextFile(zFile);
            return false;
        }
        result.push_back(std::make_tuple(fileName, std::move(sb), readFileSize));
        unzCloseCurrentFile(zFile);
        unzGoToNextFile(zFile);
    }
    return true;
}

bool CodeSigning::CheckUnzParam(unzFile& zFile, unz_file_info& zFileInfo,
                                char fileName[], size_t* nameLen)
{
    if (UNZ_OK != unzGetCurrentFileInfo(zFile, &zFileInfo, fileName,
        FILE_NAME_SIZE, NULL, 0, NULL, 0)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "unzGetCurrentFileInfo failed!");
        return false;
    }
    SIGNATURE_TOOLS_LOGI("Open zipFile filename is : %{public}s\n", fileName);
    if ((*nameLen = strlen(fileName)) == 0U) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "fileName is null");
        return false;
    }
    if (UNZ_OK != unzOpenCurrentFile(zFile)) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR,
                            "Open zipFile filename is : %{public}s failed.");
        return false;
    }
    return true;
}

bool CodeSigning::CheckFileName(unzFile& zFile, char fileName[], size_t* nameLen)
{
    if (fileName[*nameLen - 1] == '/') {
        SIGNATURE_TOOLS_LOGI("It is dictionary.\n");
        unzCloseCurrentFile(zFile);
        unzGoToNextFile(zFile);
        return false;
    }
    std::string str(fileName);
    bool nativeFileFlag = IsNativeFile(str);
    if (!nativeFileFlag) {
        SIGNATURE_TOOLS_LOGI("Suffix mismatched.\n");
        unzCloseCurrentFile(zFile);
        unzGoToNextFile(zFile);
        return false;
    }
    return true;
}

std::string CodeSigning::SplitFileName(const std::string& path)
{
    size_t found = path.find_last_of("/");
    if (found == std::string::npos) {
        found = 0;
    } else {
        ++found;
    }
    return path.substr(found);
}

bool CodeSigning::IsNativeFile(std::string& input)
{
    size_t dotPos = input.rfind('.');
    if (dotPos == std::string::npos) {
        return false;
    }
    std::string suffix = input.substr(dotPos + 1);
    return suffix == "an" || suffix == "so";
}

bool CodeSigning::SignFilesFromJar(std::vector<std::tuple<std::string,
    std::stringbuf, uLong>>&entryNames,
                                   std::string& packageName, const std::string& ownerID,
                                   std::vector<std::pair<std::string, SignInfo>>& ret)
{
    for (int i = 0; i < static_cast<int>(entryNames.size()); i++) {
        std::istream input(&(std::get<TUPLE_BUF_INDEX>(entryNames[i])));
        std::pair<SignInfo, std::vector<int8_t>> pairSignInfoAndMerkleTreeBytes;
        bool signFileFlag = SignFile(input, std::get<TUPLE_SIZE_INDEX>(entryNames[i]), false, 0, ownerID,
                                     pairSignInfoAndMerkleTreeBytes);
        if (!signFileFlag) {
            PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "signFile Failed in SignFilesFromJar");
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

bool CodeSigning::GenerateSignature(std::vector<int8_t>& signedData, const std::string& ownerID,
                                    std::vector<int8_t>& ret)
{
    if (signConfig->GetSigner() != nullptr) {
        if (signConfig->GetSigner()->GetCertificates() == nullptr) {
            PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR,
                                "No certificates configured for sign.");
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
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "generateSignature Verity digest is null");
        return false;
    }
    bool generateSignedDataFlag = bcSignedDataGenerator->GenerateSignedData(signed_data, signConfig, ret_str);
    if (generateSignedDataFlag) {
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "failed to GenerateSignedData unsigned data!");
        return false;
    }
    ret = std::vector<int8_t>(ret_str.begin(), ret_str.end());
    return true;
}
} // namespace SignatureTools
} // namespace OHOS
