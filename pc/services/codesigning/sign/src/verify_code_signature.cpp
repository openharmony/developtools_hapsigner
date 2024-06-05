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
#include "verify_code_signature.h"
#include "elf_sign_block.h"
using namespace OHOS::SignatureTools;

bool VerifyCodeSignature::VerifyHap(std::string file, int64_t offset, int64_t length,
    std::string fileFormat, std::string profileContent)
{
    if (std::find(CodeSigning::SUPPORT_FILE_FORM.begin(), CodeSigning::SUPPORT_FILE_FORM.end(),
        fileFormat) == CodeSigning::SUPPORT_FILE_FORM.end()) {
        SIGNATURE_TOOLS_LOGI("Not hap, hsp or hqf file, skip code signing verify\n");
        return true;
    }
    // 1) generate CodeSignBlock
    std::pair<std::string, std::string> pairResult = HapUtils::parseAppIdentifier(profileContent);
    CodeSignBlock csb;
    if (!GenerateCodeSignBlock(file, offset, length, csb)) {
        return false;
    }
    // 2) verify hap
    if (!VerifyCodeSign(file, pairResult, csb)) {
        return false;
    }
    return true;
}

bool VerifyCodeSignature::VerifyElf(std::string file, int64_t offset, int64_t length,
    std::string fileFormat, std::string profileContent)
{
    std::transform(fileFormat.begin(), fileFormat.end(), fileFormat.begin(), ::tolower);
    if (CodeSigning::SUPPORT_BIN_FILE_FORM != fileFormat) {
        SIGNATURE_TOOLS_LOGE("Not elf file, skip code signing verify\n");
        return false;
    }
    // 1) parse sign block to ElfSignBlock object
    std::ifstream signedElf(file, std::ios::binary);
    if (!signedElf.is_open()) {
        SIGNATURE_TOOLS_LOGE("read %{public}s file failed.", file.c_str());
        return false;
    }
    signedElf.seekg(offset, std::ios::beg);
    std::vector<int8_t> codeSignBlockBytes(length);
    signedElf.read((char*)codeSignBlockBytes.data(), codeSignBlockBytes.size());
    signedElf.close();
    ElfSignBlock elfSignBlock;
    if (!ElfSignBlock::FromByteArray(codeSignBlockBytes, elfSignBlock)) {
        SIGNATURE_TOOLS_LOGE("parse sign block to ElfCodeSignBlock object failed\n");
        return false;
    }
    // 2) verify file data
    int32_t paddingSize = ElfSignBlock::ComputeMerkleTreePaddingLength(offset);
    std::vector<int8_t> merkleTreeWithPadding = elfSignBlock.GetMerkleTreeWithPadding();
    std::vector<int8_t> merkleTree;
    merkleTree.insert(merkleTree.end(), merkleTreeWithPadding.begin() + paddingSize, merkleTreeWithPadding.end());
    std::ifstream elf(file, std::ios::binary);
    if (!VerifySingleFile(elf, elfSignBlock.GetDataSize(), elfSignBlock.GetSignature(),
        elfSignBlock.GetTreeOffset(), merkleTree)) {
        SIGNATURE_TOOLS_LOGE("verify elf file data failed\n");
        elf.close();
        return false;
    }
    elf.close();
    // 3) check ownerID
    if (!profileContent.empty()) {
        std::pair<std::string, std::string> pairResult = HapUtils::parseAppIdentifier(profileContent);
        std::vector<int8_t> signature = elfSignBlock.GetSignature();
        std::string signatureStr(signature.begin(), signature.end());
        if (!CmsUtils::CheckOwnerID(signatureStr, pairResult.first, pairResult.second)) {
            SIGNATURE_TOOLS_LOGE("elf check owner id failed\n");
            return false;
        }
    }
    return true;
}

bool VerifyCodeSignature::VerifyNativeLib(CodeSignBlock& csb, std::string &file, unzFile &zFile,
    std::pair<std::string, std::string>& pairResult)
{
    std::vector<std::tuple<std::string, std::stringbuf, uLong>> nativeEntries
        = CodeSigning::GetNativeEntriesFromHap(file);
    if (nativeEntries.empty()) {
        SIGNATURE_TOOLS_LOGI("No native libs to verify.\n");
        return true;
    }
    for (int i = 0; i < csb.getSoInfoSegment().getSectionNum(); i++) {
        SignInfo signInfo = csb.getSoInfoSegment().getSignInfoList()[i];
        std::string entryName = csb.getSoInfoSegment().getFileNameList()[i];
        std::vector<int8_t> entrySig = signInfo.getSignature();
        std::string entrySigStr(entrySig.begin(), entrySig.end());
        for (int j = 0; j < static_cast<int>(nativeEntries.size()); j++) {
            if (std::get<0>(nativeEntries[j]) != entryName) {
                continue;
            }
            int64_t entrySize = std::get<2>(nativeEntries[j]);
            if (entrySize != signInfo.getDataSize()) {
                SIGNATURE_TOOLS_LOGE("Invalid dataSize of native lib %{public}s\n", entryName.c_str());
                unzClose(zFile);
                return false;
            }
            std::istream entryInputStream(&(std::get<1>(nativeEntries[j])));
            if (!VerifySingleFile(entryInputStream, entrySize, entrySig, 0, std::vector<int8_t>())) {
                unzClose(zFile);
                return false;
            }
            std::ifstream* inputFile = (std::ifstream*)(&entryInputStream);
            inputFile->close();
            if (!CmsUtils::CheckOwnerID(entrySigStr, pairResult.first, pairResult.second)) {
                unzClose(zFile);
                return false;
            }
            break;
        }
    }
    return true;
}

bool VerifyCodeSignature::VerifyCodeSign(std::string file, std::pair<std::string, std::string>& pairResult,
    CodeSignBlock& csb)
{
    // 1) verify hap
    std::ifstream hap(file, std::ios::binary);
    if (!hap.is_open()) {
        SIGNATURE_TOOLS_LOGE("VerifyCodeSign Failed to open hap file\n");
        return false;
    }
    int64_t dataSize = csb.getHapInfoSegment().getSignInfo().getDataSize();
    std::vector<int8_t> signature = csb.getHapInfoSegment().getSignInfo().getSignature();
    Extension* ext = csb.getHapInfoSegment().getSignInfo()
        .getExtensionByType(MerkleTreeExtension::MERKLE_TREE_INLINED);
    MerkleTreeExtension* mte = new MerkleTreeExtension(0, 0, std::vector<int8_t>());
    if (ext != nullptr) {
        delete mte;
        mte = (MerkleTreeExtension*)(ext);
    } else {
        std::shared_ptr<MerkleTreeExtension> merkleTreeExt(mte);
    }
    // temporary: merkle tree offset set to zero, change to merkleTreeOffset
    if (!VerifySingleFile(hap, dataSize, signature, mte->getMerkleTreeOffset(),
        csb.getOneMerkleTreeByFileName(CodeSigning::HAP_SIGNATURE_ENTRY_NAME))) {
        return false;
    }
    hap.close();
    std::string signature_(signature.begin(), signature.end());
    if (!CmsUtils::CheckOwnerID(signature_, pairResult.first, pairResult.second)) {
        return false;
    }
    // 2) verify native libs
    unzFile zFile = unzOpen(file.c_str());
    if (zFile == NULL) {
        SIGNATURE_TOOLS_LOGE("unzOpen failed\n");
        return false;
    }
    if (!VerifyNativeLib(csb, file, zFile, pairResult)) {
        return false;
    }
    unzClose(zFile);
    return true;
}
bool VerifyCodeSignature::VerifySingleFile(std::istream& input, int64_t length,
    std::vector<int8_t> signature, int64_t merkleTreeOffset, std::vector<int8_t> inMerkleTreeBytes)
{
    std::pair<std::vector<int8_t>, std::vector<int8_t>> pairResult
        = GenerateFsVerityDigest(input, length, merkleTreeOffset);
    std::vector<int8_t> generatedMerkleTreeBytes = pairResult.second;
    // For native libs, inMerkleTreeBytes is null, skip check here
    if ((!inMerkleTreeBytes.empty()) && !AreVectorsEqual(inMerkleTreeBytes, generatedMerkleTreeBytes)) {
        SIGNATURE_TOOLS_LOGE("verify merkle tree bytes failed");
        return false;
    }
    return CmsUtils::VerifySignDataWithUnsignedDataDigest(pairResult.first, signature);
}
bool VerifyCodeSignature::GenerateCodeSignBlock(const std::string& file, int64_t offset,
    int64_t length, CodeSignBlock& csb)
{
    // 1) parse sign block to CodeSignBlock object
    std::ifstream signedHap(file, std::ios::binary);
    if (!signedHap.is_open()) {
        SIGNATURE_TOOLS_LOGE("read %{public}s file failed.", file.c_str());
        return false;
    }
    int32_t fileReadOffset = 0;
    // 1.1) skip data part, but fileReadOffset remains at start(0)
    signedHap.seekg(offset, std::ios::beg);
    // 1.2) parse codeSignBlockHeader
    std::vector<int8_t> codeSignBlockHeaderByteArray(CodeSignBlockHeader::size());
    signedHap.read((char*)codeSignBlockHeaderByteArray.data(), codeSignBlockHeaderByteArray.size());
    fileReadOffset += signedHap.gcount();
    CodeSignBlockHeader* pCodeSignBlockHeader = CodeSignBlockHeader::fromByteArray(codeSignBlockHeaderByteArray);
    if (nullptr == pCodeSignBlockHeader) {
        SIGNATURE_TOOLS_LOGE("Invalid code Sign block header");
        signedHap.close();
        return false;
    }
    std::shared_ptr<CodeSignBlockHeader> codeSignBlockHeader(pCodeSignBlockHeader);
    csb.setCodeSignBlockHeader(*codeSignBlockHeader);
    if (csb.getCodeSignBlockHeader().getBlockSize() != length) {
        SIGNATURE_TOOLS_LOGE("Invalid code Sign block size of setCodeSignBlockHeader");
        signedHap.close();
        return false;
    }
    // 2) parse segment headers
    for (int i = 0; i < csb.getCodeSignBlockHeader().getSegmentNum(); i++) {
        std::vector<int8_t> segmentHeaderByteArray(SegmentHeader::SEGMENT_HEADER_LENGTH);
        signedHap.read((char*)segmentHeaderByteArray.data(), segmentHeaderByteArray.size());
        fileReadOffset += signedHap.gcount();
        csb.addToSegmentList(*SegmentHeader::fromByteArray(segmentHeaderByteArray));
    }
    // compute merkle tree offset by alignment, based on file start
    int64_t computedTreeOffset = GetAlignmentAddr(CodeSignBlock::PAGE_SIZE_4K, fileReadOffset + offset);
    // skip zero padding before merkle tree, adds zero padding length to fileReadOffset
    signedHap.seekg(computedTreeOffset - offset - fileReadOffset, std::ios::cur);
    fileReadOffset += computedTreeOffset - offset - fileReadOffset;
    if (!ParseMerkleTree(csb, fileReadOffset, signedHap, computedTreeOffset)) {
        SIGNATURE_TOOLS_LOGE("parse merkle tree failed.");
        return false;
    }
    signedHap.close();
    return true;
}
bool VerifyCodeSignature::ParseMerkleTree(CodeSignBlock& csb, int32_t readOffset, std::ifstream& signedHap,
    int64_t computedTreeOffset)
{
    std::vector<int8_t> merkleTreeBytes;
    int32_t fileReadOffset = readOffset;
    for (auto& segmentHeader : csb.getSegmentHeaderList()) {
        if (fileReadOffset > segmentHeader.getSegmentOffset()) {
            SIGNATURE_TOOLS_LOGE("Invaild offset of merkle tree and segment header");
            return false;
        }
        // get merkle tree bytes
        if (fileReadOffset < segmentHeader.getSegmentOffset()) {
            merkleTreeBytes.resize(segmentHeader.getSegmentOffset() - fileReadOffset);
            signedHap.read((char*)merkleTreeBytes.data(), merkleTreeBytes.size());
            fileReadOffset += signedHap.gcount();
        }
        std::vector<int8_t> sh(segmentHeader.getSegmentSize(), 0);
        signedHap.read((char*)sh.data(), sh.size());
        fileReadOffset += signedHap.gcount();
        if (segmentHeader.getType() == SegmentHeader::CSB_FSVERITY_INFO_SEG) {
            // 3) parse fs-verity info segment
            FsVerityInfoSegment fsVerityInfoSegment = FsVerityInfoSegment::fromByteArray(sh);
            csb.setFsVerityInfoSegment(fsVerityInfoSegment);
        } else if (segmentHeader.getType() == SegmentHeader::CSB_HAP_META_SEG) {
            // 4) parse hap info segment
            HapInfoSegment hapInfoSegment = HapInfoSegment::fromByteArray(sh);
            csb.setHapInfoSegment(hapInfoSegment);
        } else if (segmentHeader.getType() == SegmentHeader::CSB_NATIVE_LIB_INFO_SEG) {
            // 5) parse so info segment
            NativeLibInfoSegment nativeLibInfoSegment = NativeLibInfoSegment::fromByteArray(sh);
            csb.setSoInfoSegment(nativeLibInfoSegment);
        }
    }
    if (fileReadOffset != csb.getCodeSignBlockHeader().getBlockSize()) {
        SIGNATURE_TOOLS_LOGE("Invalid blockSize of getCodeSignBlockHeader");
        return false;
    }
    // parse merkle tree
    Extension* extension = csb.getHapInfoSegment().getSignInfo().
        getExtensionByType(MerkleTreeExtension::MERKLE_TREE_INLINED);
    if (!extension) {
        SIGNATURE_TOOLS_LOGE("Missing merkleTreeExtension in verifycation");
        return false;
    }
    MerkleTreeExtension* mte = (MerkleTreeExtension*)(extension);
    if (mte) {
        if (computedTreeOffset != mte->getMerkleTreeOffset() || merkleTreeBytes.size() != mte->getMerkleTreeSize()) {
            SIGNATURE_TOOLS_LOGE("Invalid merkle tree offset or tree size");
            return false;
        }
        csb.addOneMerkleTree(CodeSigning::HAP_SIGNATURE_ENTRY_NAME, merkleTreeBytes);
    }
    return true;
}
int64_t VerifyCodeSignature::GetAlignmentAddr(int64_t alignment, int64_t input)
{
    if(alignment == 0)
        return input;
    int64_t residual = input % alignment;
    if (residual == 0) return input;
    else return input + (alignment - residual);
}
std::pair<std::vector<int8_t>, std::vector<int8_t>> VerifyCodeSignature::GenerateFsVerityDigest(
    std::istream& inputStream, int64_t size, int64_t merkleTreeOffset)
{
    std::unique_ptr<FsVerityGenerator> fsVerityGenerator = std::make_unique<FsVerityGenerator>(FsVerityGenerator());
    fsVerityGenerator->GenerateFsVerityDigest(inputStream, size, merkleTreeOffset);
    return std::make_pair(fsVerityGenerator->GetFsVerityDigest(), fsVerityGenerator->GetTreeBytes());
}
bool VerifyCodeSignature::AreVectorsEqual(const std::vector<int8_t>& vec1, const std::vector<int8_t>& vec2)
{
    if (vec1.size() != vec2.size()) {
        return false;
    }
    for (int64_t i = 0; i < vec1.size(); i++) {
        if (vec1[i] != vec2[i]) {
            return false;
        }
    }
    return true;
}