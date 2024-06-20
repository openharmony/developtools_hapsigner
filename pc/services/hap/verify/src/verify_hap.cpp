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
#include <climits>
#include <cstdlib>
#include <regex>
#include <unordered_map>
#include <vector>

#include "securec.h"
#include "profile_verify_utils.h"
#include "hap_signer_block_utils.h"
#include "signature_info.h"
#include "options.h"
#include "openssl/pem.h"
#include "pkcs7_data.h"
#include "hap_utils.h"
#include "string_utils.h"
#include "unsigned_decimal_util.h"
#include "verify_code_signature.h"
#include "param_constants.h"
#include "file_utils.h"
#include "nlohmann/json.hpp"
#include "verify_hap.h"

using namespace nlohmann;
namespace OHOS {
namespace SignatureTools {
const int32_t VerifyHap::HEX_PRINT_LENGTH = 3;
const int32_t VerifyHap::DIGEST_BLOCK_LEN_OFFSET = 8;
const int32_t VerifyHap::DIGEST_ALGORITHM_OFFSET = 12;
const int32_t VerifyHap::DIGEST_LEN_OFFSET = 16;
const int32_t VerifyHap::DIGEST_OFFSET_IN_CONTENT = 20;
const std::string VerifyHap::HAP_APP_PATTERN = "[^]*.hap$";
const std::string VerifyHap::HQF_APP_PATTERN = "[^]*.hqf$";
const std::string VerifyHap::HSP_APP_PATTERN = "[^]*.hsp$";
const std::string VerifyHap::APP_APP_PATTERN = "[^]*.app$";
static constexpr int ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH = 12;
bool VerifyHap::HapOutPutPkcs7(PKCS7* p7, const std::string& outPutPath)
{
    std::string p7bContent = StringUtils::Pkcs7ToString(p7);
    if (p7bContent.empty()) {
        SIGNATURE_TOOLS_LOGE("p7b to string failed!\n");
        return false;
    }
    if (FileUtils::Write(p7bContent, outPutPath) < 0) {
        SIGNATURE_TOOLS_LOGE("p7b write to file falied!\n");
        return false;
    }
    return true;
}

bool VerifyHap::HapOutPutCertChain(std::vector<X509*>& certs, const std::string& outPutPath)
{
    VerifyHapOpensslUtils::GetOpensslErrorMessage();
    SIGNATURE_TOOLS_LOGD("outPutPath = %{public}s", outPutPath.c_str());
    std::vector<std::string> certStr;
    for (auto& cert : certs) {
        certStr.emplace_back(StringUtils::SubjectToString(cert));
        certStr.emplace_back(StringUtils::x509CertToString(cert));
    }
    std::string outPutCertChainContent;
    for (auto& certstr : certStr) {
        outPutCertChainContent += certstr;
    }
    if (FileUtils::Write(outPutCertChainContent, outPutPath) < 0) {
        SIGNATURE_TOOLS_LOGE("certChain write to file falied!\n");
        return false;
    }
    return true;
}

int32_t VerifyHap::Verify(const std::string& filePath, HapVerifyResult& hapVerifyV1Result, Options* options)
{
    SIGNATURE_TOOLS_LOGD("Start Verify");
    std::string standardFilePath;
    if (!CheckFilePath(filePath, standardFilePath)) {
        PrintErrorNumberMsg("Verify_hap", FILE_PATH_INVALID, "file:" + filePath + " path is invalid");
        return FILE_PATH_INVALID;
    }
    RandomAccessFile hapFile;
    if (!hapFile.Init(standardFilePath)) {
        PrintErrorNumberMsg("Verify_hap", OPEN_FILE_ERROR, standardFilePath + " open failed");
        return OPEN_FILE_ERROR;
    }
    int32_t resultCode = Verify(hapFile, hapVerifyV1Result, options, filePath);
    if (resultCode != VERIFY_SUCCESS) {
        PrintErrorNumberMsg("Verify_hap", resultCode, standardFilePath + " verify failed");
    }
    return resultCode;
}

bool VerifyHap::CheckFilePath(const std::string& filePath, std::string& standardFilePath)
{
    char path[PATH_MAX] = { 0x00 };
    if (filePath.size() > PATH_MAX || realpath(filePath.c_str(), path) == nullptr) {
        SIGNATURE_TOOLS_LOGE("filePath is not a standard path");
        return false;
    }
    standardFilePath = std::string(path);
    bool ret = (!std::regex_match(standardFilePath, std::regex(HAP_APP_PATTERN)) &&
                !std::regex_match(standardFilePath, std::regex(HSP_APP_PATTERN)) &&
                !std::regex_match(standardFilePath, std::regex(APP_APP_PATTERN)) &&
                !std::regex_match(standardFilePath, std::regex(HQF_APP_PATTERN)));
    if (ret) {
        SIGNATURE_TOOLS_LOGE("file is not hap, hsp or hqf package");
        return false;
    }
    return true;
}

int32_t VerifyHap::InithapVerify(RandomAccessFile& hapFile, const std::string& filePath,
                                 SignatureInfo& hapSignInfo, HapVerifyResult& hapVerifyV1Result)
{
    if (!HapSignerBlockUtils::FindHapSignature(hapFile, hapSignInfo)) {
        return SIGNATURE_NOT_FOUND;
    }
    if (CheckCodeSign(filePath, hapSignInfo.optionBlocks) == false) {
        SIGNATURE_TOOLS_LOGE("check coode sign failed\n");
        return VERIFY_CODE_SIGN_FAIL;
    }
    hapVerifyV1Result.SetVersion(hapSignInfo.version);
    hapVerifyV1Result.SetPkcs7SignBlock(hapSignInfo.hapSignatureBlock);
    hapVerifyV1Result.SetPkcs7ProfileBlock(hapSignInfo.hapSignatureBlock);
    hapVerifyV1Result.SetOptionalBlocks(hapSignInfo.optionBlocks);
    return VERIFY_SUCCESS;
}

int32_t VerifyHap::Verify(RandomAccessFile& hapFile, HapVerifyResult& hapVerifyV1Result,
                          Options* options, const std::string& filePath)
{
    SignatureInfo hapSignInfo;
    if (InithapVerify(hapFile, filePath, hapSignInfo, hapVerifyV1Result) != VERIFY_SUCCESS)
        return SIGNATURE_NOT_FOUND;
    Pkcs7Context pkcs7Context;
    if (!VerifyAppPkcs7(pkcs7Context, hapSignInfo.hapSignatureBlock)) {
        return VERIFY_APP_PKCS7_FAIL;
    }
    int32_t profileIndex = 0;
    if (!HapSignerBlockUtils::GetOptionalBlockIndex(hapSignInfo.optionBlocks, PROFILE_BLOB, profileIndex)) {
        return NO_PROFILE_BLOCK_FAIL;
    }
    bool profileNeedWriteCrl = false;
    if (!VerifyAppSourceAndParseProfile(pkcs7Context, hapSignInfo.optionBlocks[profileIndex].optionalBlockValue,
        hapVerifyV1Result, profileNeedWriteCrl)) {
        SIGNATURE_TOOLS_LOGE("APP source is not trusted");
        return APP_SOURCE_NOT_TRUSTED;
    }
    if (!GetDigestAndAlgorithm(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("Get digest failed");
        return GET_DIGEST_FAIL;
    }
    std::vector<std::string> publicKeys;
    if (!VerifyHapOpensslUtils::GetPublickeys(pkcs7Context.certChains[0], publicKeys)) {
        SIGNATURE_TOOLS_LOGE("Get publicKeys failed");
        return GET_PUBLICKEY_FAIL;
    }
    hapVerifyV1Result.SetPublicKey(publicKeys);
    std::vector<std::string> certSignatures;
    if (!VerifyHapOpensslUtils::GetSignatures(pkcs7Context.certChains[0], certSignatures)) {
        SIGNATURE_TOOLS_LOGE("Get sianatures failed");
        return GET_SIGNATURE_FAIL;
    }
    hapVerifyV1Result.SetSignature(certSignatures);
    if (!HapSignerBlockUtils::VerifyHapIntegrity(pkcs7Context, hapFile, hapSignInfo)) {
        SIGNATURE_TOOLS_LOGE("Verify Integrity failed");
        return VERIFY_INTEGRITY_FAIL;
    }
    if (!VerifyHap::HapOutPutCertChain(pkcs7Context.certChains[0],
        options->GetString(Options::OUT_CERT_CHAIN))) {
        SIGNATURE_TOOLS_LOGE("out put cert chain failed");
        return OUT_PUT_FILE_FAIL;
    }
    if (!VerifyHap::HapOutPutPkcs7(pkcs7Context.p7, options->GetString(Options::OUT_PROFILE))) {
        SIGNATURE_TOOLS_LOGE("out put p7b failed");
        return OUT_PUT_FILE_FAIL;
    }
    return VERIFY_SUCCESS;
}

bool VerifyHap::CheckCodeSign(const std::string& hapFilePath,
                              const std::vector<OptionalBlock>& optionalBlocks)const
{
    std::unordered_map<int, ByteBuffer> map;
    for (const OptionalBlock& block : optionalBlocks) {
        map.emplace(block.optionalType, block.optionalBlockValue);
    }
    bool codeSignFlag = map.find(HapUtils::HAP_PROPERTY_BLOCK_ID) != map.end() &&
        map[HapUtils::HAP_PROPERTY_BLOCK_ID].GetCapacity() > 0;
    if (codeSignFlag) {
        ByteBuffer propertyBlockArray = map[HapUtils::HAP_PROPERTY_BLOCK_ID];
        std::vector<std::string> fileNameArray = StringUtils::SplitString(hapFilePath, '.');
        if (fileNameArray.size() < ParamConstants::FILE_NAME_MIN_LENGTH) {
            SIGNATURE_TOOLS_LOGE("ZIP64 format not supported\n");
            return false;
        }
        
        if (propertyBlockArray.GetCapacity() < ZIP_HEAD_OF_SUBSIGNING_BLOCK_LENGTH)
            return false;
        uint32_t blockType;
        propertyBlockArray.GetUInt32(0,blockType);
        uint32_t blockLength;
        propertyBlockArray.GetUInt32(4, blockLength);
        uint32_t blockOffset;
        propertyBlockArray.GetUInt32(8, blockOffset);

        if (blockType != HapUtils::HAP_CODE_SIGN_BLOCK_ID) {
            SIGNATURE_TOOLS_LOGE("Verify Hap has no code sign data error!\n");
            return false;
        }
        auto ite = map.find(HapUtils::HAP_PROFILE_BLOCK_ID);
        if (ite == map.end())
            return false;
        ByteBuffer profileArray = ite->second;
        std::string profileArray_(profileArray.GetBufferPtr(), profileArray.GetCapacity());
        std::string profileContent;
        if (GetProfileContent(profileArray_, profileContent) < 0) {
            SIGNATURE_TOOLS_LOGE("get profile content failed\n");
            return false;
        }
        std::string suffix = fileNameArray[fileNameArray.size() - 1];
        bool isCodeSign = VerifyCodeSignature::VerifyHap(hapFilePath, blockOffset, blockLength,
                                                         suffix, profileContent);
        if (!isCodeSign) {
            SIGNATURE_TOOLS_LOGE("Verify Hap has no code sign data error!\n");
            return false;
        }
        SIGNATURE_TOOLS_LOGI("verify codesign success\n");
        return true;
    }
    SIGNATURE_TOOLS_LOGI("can not find codesign block\n");
    return true;
}

int VerifyHap::GetProfileContent(const std::string profile, std::string& ret)
{
    json obj = json::parse(profile, nullptr, false);
    if (!obj.is_discarded() && obj.is_structured()) {
        ret = profile;
        return 0;
    }
    PKCS7Data p7Data;
    if (p7Data.Parse(profile) < 0) {
        PrintErrorNumberMsg("PKCS7_PARSE_ERROR", PKCS7_PARSE_ERROR, "Parse profile failed");
        ret = profile;
        return -1;
    }
    if (p7Data.Verify() < 0) {
        PrintErrorNumberMsg("PKCS7_VERIFY_ERROR", PKCS7_VERIFY_ERROR,
                            "Verify profile pkcs7 failed! Profile is invalid");
        ret = profile;
        return -1;
    }
    if (p7Data.GetContent(ret) < 0) {
        PrintErrorNumberMsg("PKCS7_VERIFY_ERROR", PKCS7_VERIFY_ERROR,
                            "Check profile failed, signed profile content is not byte array");
        ret = profile;
        return -1;
    }
    return 0;
}

bool VerifyHap::VerifyAppPkcs7(Pkcs7Context& pkcs7Context, const ByteBuffer& hapSignatureBlock)
{
    const unsigned char* pkcs7Block = reinterpret_cast<const unsigned char*>(hapSignatureBlock.GetBufferPtr());
    uint32_t pkcs7Len = static_cast<unsigned int>(hapSignatureBlock.GetCapacity());
    if (!VerifyHapOpensslUtils::ParsePkcs7Package(pkcs7Block, pkcs7Len, pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("parse pkcs7 failed");
        return false;
    }
    if (!VerifyHapOpensslUtils::GetCertChains(pkcs7Context.p7, pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("GetCertChains from pkcs7 failed");
        return false;
    }
    if (!VerifyHapOpensslUtils::VerifyPkcs7(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("verify signature failed");
        return false;
    }
    return true;
}

bool VerifyHap::VerifyAppSourceAndParseProfile(Pkcs7Context& pkcs7Context,
                                               const ByteBuffer& hapProfileBlock,
                                               HapVerifyResult& hapVerifyV1Result,
                                               bool& profileNeadWriteCrl)
{
    std::string certSubject;
    if (!VerifyCertOpensslUtils::GetSubjectFromX509(pkcs7Context.certChains[0][0], certSubject)) {
        SIGNATURE_TOOLS_LOGE("Get info of sign cert failed");
        return false;
    }
    SIGNATURE_TOOLS_LOGD("App signature subject: %{public}s, issuer: %{public}s",
                         certSubject.c_str(), pkcs7Context.certIssuer.c_str());
    if (!NeedParseJson(hapProfileBlock)) return true;
    Pkcs7Context profileContext;
    std::string profile;
    if (!ProfileVerifyUtils::ParseProfile(profileContext, pkcs7Context, hapProfileBlock, profile)) {
        SIGNATURE_TOOLS_LOGE("Parse profile pkcs7 failed");
        return false;
    }
    if (!VerifyProfileSignature(pkcs7Context, profileContext)) {
        SIGNATURE_TOOLS_LOGE("VerifyProfileSignature failed");
        return false;
    }
    /*
     * If app source is not trusted, verify profile.
     * If profile is debug, check whether app signed cert is same as the debug cert in profile.
     * If profile is release, do not allow installation of this app.
     */
    bool isCallParseAndVerify = false;
    ProfileInfo provisionInfo;
    if (pkcs7Context.matchResult.matchState == DO_NOT_MATCH) {
        if (!ProfileVerifyUtils::VerifyProfile(profileContext)) {
            SIGNATURE_TOOLS_LOGE("profile verify failed");
            return false;
        }
        AppProvisionVerifyResult profileRet = ParseAndVerify(profile, provisionInfo);
        if (profileRet != PROVISION_OK) {
            SIGNATURE_TOOLS_LOGE("profile parsing failed, error: %{public}d", static_cast<int>(profileRet));
            return false;
        }
        if (!VerifyProfileInfo(pkcs7Context, profileContext, provisionInfo)) {
            SIGNATURE_TOOLS_LOGE("VerifyProfileInfo failed");
            return false;
        }
        isCallParseAndVerify = true;
    }
    if (!ParseAndVerifyProfileIfNeed(profile, provisionInfo, isCallParseAndVerify)) {
        return false;
    }
    if (!GenerateAppId(provisionInfo) || !GenerateFingerprint(provisionInfo)) {
        SIGNATURE_TOOLS_LOGE("Generate appId or generate fingerprint failed");
        return false;
    }
    SetOrganization(provisionInfo);
    SetProfileBlockData(pkcs7Context, hapProfileBlock, provisionInfo);
    hapVerifyV1Result.SetProvisionInfo(provisionInfo);
    profileNeadWriteCrl = profileContext.needWriteCrl;
    return true;
}

bool VerifyHap::NeedParseJson(const ByteBuffer& buffer)
{
    std::string profileArray_(buffer.GetBufferPtr(), buffer.GetCapacity());
    json obj = json::parse(profileArray_, nullptr, false);
    if (!obj.is_discarded() && obj.is_structured()) {
        return false;
    }
    return true;
}

bool VerifyHap::VerifyProfileSignature(const Pkcs7Context& pkcs7Context, Pkcs7Context& profileContext)
{
    if (pkcs7Context.matchResult.matchState == MATCH_WITH_SIGN &&
        pkcs7Context.matchResult.source == APP_THIRD_PARTY_PRELOAD) {
        if (!ProfileVerifyUtils::VerifyProfile(profileContext)) {
            SIGNATURE_TOOLS_LOGE("profile verify failed");
            return false;
        }
    }
    return true;
}

bool VerifyHap::GenerateAppId(ProfileInfo& provisionInfo)
{
    std::string& certInProfile = provisionInfo.bundleInfo.distributionCertificate;
    if (provisionInfo.bundleInfo.distributionCertificate.empty()) {
        certInProfile = provisionInfo.bundleInfo.developmentCertificate;
        SIGNATURE_TOOLS_LOGD("use development Certificate");
    }
    std::string publicKey;
    if (!VerifyCertOpensslUtils::GetPublickeyBase64FromPemCert(certInProfile, publicKey)) {
        return false;
    }
    provisionInfo.appId = publicKey;
    SIGNATURE_TOOLS_LOGD("provisionInfo.appId: %{public}s", provisionInfo.appId.c_str());
    return true;
}

bool VerifyHap::GenerateFingerprint(ProfileInfo& provisionInfo)
{
    std::string& certInProfile = provisionInfo.bundleInfo.distributionCertificate;
    if (provisionInfo.bundleInfo.distributionCertificate.empty()) {
        certInProfile = provisionInfo.bundleInfo.developmentCertificate;
        SIGNATURE_TOOLS_LOGD("use development Certificate");
    }
    std::string fingerprint;
    if (!VerifyCertOpensslUtils::GetFingerprintBase64FromPemCert(certInProfile, fingerprint)) {
        SIGNATURE_TOOLS_LOGE("Generate fingerprint from pem certificate failed");
        return false;
    }
    provisionInfo.fingerprint = fingerprint;
    SIGNATURE_TOOLS_LOGD("fingerprint is : %{public}s", fingerprint.c_str());
    return true;
}

void VerifyHap::SetProfileBlockData(const Pkcs7Context& pkcs7Context, const ByteBuffer& hapProfileBlock,
                                    ProfileInfo& provisionInfo)
{
    if (pkcs7Context.matchResult.matchState == MATCH_WITH_SIGN &&
        pkcs7Context.matchResult.source == APP_GALLARY) {
        SIGNATURE_TOOLS_LOGD("profile is from app gallary and unnecessary to set profile block");
        return;
    }
    provisionInfo.profileBlockLength = hapProfileBlock.GetCapacity();
    SIGNATURE_TOOLS_LOGD("profile block data length is %{public}d", provisionInfo.profileBlockLength);
    if (provisionInfo.profileBlockLength == 0) {
        SIGNATURE_TOOLS_LOGE("invalid profile block");
        return;
    }
    provisionInfo.profileBlock = std::make_unique<unsigned char[]>(provisionInfo.profileBlockLength);

    if (memcpy_s(provisionInfo.profileBlock.get(), provisionInfo.profileBlockLength,
        hapProfileBlock.GetBufferPtr(),
        provisionInfo.profileBlockLength) != 0) {
        SIGNATURE_TOOLS_LOGE("memcpy failed");
    }
}

bool VerifyHap::VerifyProfileInfo(const Pkcs7Context& pkcs7Context, const Pkcs7Context& profileContext,
                                  ProfileInfo& provisionInfo)
{
    std::string& certInProfile = provisionInfo.bundleInfo.developmentCertificate;
    if (provisionInfo.type == ProvisionType::RELEASE) {
        if (!IsAppDistributedTypeAllowInstall(provisionInfo.distributionType, provisionInfo)) {
            SIGNATURE_TOOLS_LOGE("untrusted source app with release profile distributionType: %{public}d",
                                 static_cast<int>(provisionInfo.distributionType));
            return false;
        }
        certInProfile = provisionInfo.bundleInfo.distributionCertificate;
        SIGNATURE_TOOLS_LOGD("allow install app with release profile distributionType: %{public}d",
                             static_cast<int>(provisionInfo.distributionType));
    }
    SIGNATURE_TOOLS_LOGD("provisionInfo.type: %{public}d", static_cast<int>(provisionInfo.type));
    return true;
}

bool VerifyHap::IsAppDistributedTypeAllowInstall(const AppDistType& type,
                                                 const ProfileInfo& provisionInfo) const
{
    switch (type) {
        case AppDistType::NONE_TYPE:
            return false;
        case AppDistType::APP_GALLERY:
        case AppDistType::ENTERPRISE:
        case AppDistType::ENTERPRISE_NORMAL:
        case AppDistType::ENTERPRISE_MDM:
        case AppDistType::OS_INTEGRATION:
        case AppDistType::CROWDTESTING:
            return true;
        default:
            return false;
    }
}

bool VerifyHap::ParseAndVerifyProfileIfNeed(const std::string& profile,
                                            ProfileInfo& provisionInfo, bool isCallParseAndVerify)
{
    if (isCallParseAndVerify) {
        return isCallParseAndVerify;
    }
    AppProvisionVerifyResult profileRet = ParseAndVerify(profile, provisionInfo);
    if (profileRet != PROVISION_OK) {
        SIGNATURE_TOOLS_LOGE("profile parse failed, error: %{public}d", static_cast<int>(profileRet));
        return false;
    }
    return true;
}

bool VerifyHap::GetDigestAndAlgorithm(Pkcs7Context& digest)
{
    /*
     * contentinfo format:
     * int: version
     * int: block number
     * digest blocks:
     * each digest block format:
     * int: length of sizeof(digestblock) - 4
     * int: Algorithm ID
     * int: length of digest
     * byte[]: digest
     */
     /* length of sizeof(digestblock - 4) */
    int32_t digestBlockLen;
    if (!digest.content.GetInt32(DIGEST_BLOCK_LEN_OFFSET, digestBlockLen)) {
        SIGNATURE_TOOLS_LOGE("get digestBlockLen failed");
        return false;
    }
    /* Algorithm ID */
    if (!digest.content.GetInt32(DIGEST_ALGORITHM_OFFSET, digest.digestAlgorithm)) {
        SIGNATURE_TOOLS_LOGE("get digestAlgorithm failed");
        return false;
    }
    /* length of digest */
    int32_t digestlen;
    if (!digest.content.GetInt32(DIGEST_LEN_OFFSET, digestlen)) {
        SIGNATURE_TOOLS_LOGE("get digestlen failed");
        return false;
    }
    int32_t sum = sizeof(digestlen) + sizeof(digest.digestAlgorithm) + digestlen;
    if (sum != digestBlockLen) {
        SIGNATURE_TOOLS_LOGE("digestBlockLen: %{public}d is not equal to sum: %{public}d",
                             digestBlockLen, sum);
        return false;
    }
    /* set position to the digest start point */
    digest.content.SetPosition(DIGEST_OFFSET_IN_CONTENT);
    /* set limit to the digest end point */
    digest.content.SetLimit(DIGEST_OFFSET_IN_CONTENT + digestlen);
    digest.content.Slice();
    return true;
}

void VerifyHap::SetOrganization(ProfileInfo& provisionInfo)
{
    std::string& certInProfile = provisionInfo.bundleInfo.distributionCertificate;
    if (provisionInfo.bundleInfo.distributionCertificate.empty()) {
        SIGNATURE_TOOLS_LOGE("distributionCertificate is empty");
        return;
    }
    std::string organization;
    if (!VerifyCertOpensslUtils::GetOrganizationFromPemCert(certInProfile, organization)) {
        SIGNATURE_TOOLS_LOGE("Generate organization from pem certificate failed");
        return;
    }
    provisionInfo.organization = organization;
}

int32_t VerifyHap::VerifyElfProfile(std::vector<int8_t>& profileData, HapVerifyResult& hapVerifyV1Result,
                                    Options* options, Pkcs7Context& pkcs7Context)
{
    const unsigned char* pkcs7Block = reinterpret_cast<const unsigned char*>(profileData.data());
    uint32_t pkcs7Len = static_cast<unsigned int>(profileData.size());
    if (!VerifyHapOpensslUtils::ParsePkcs7Package(pkcs7Block, pkcs7Len, pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("parse pkcs7 failed");
        return false;
    }
    if (!VerifyHapOpensslUtils::GetCertChains(pkcs7Context.p7, pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("GetCertChains from pkcs7 failed");
        return false;
    }
    if (!VerifyHapOpensslUtils::VerifyPkcs7(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("verify signature failed");
        return false;
    }
    std::vector<std::string> publicKeys;
    if (!VerifyHapOpensslUtils::GetPublickeys(pkcs7Context.certChains[0], publicKeys)) {
        SIGNATURE_TOOLS_LOGE("Get publicKeys failed");
        return GET_PUBLICKEY_FAIL;
    }
    hapVerifyV1Result.SetPublicKey(publicKeys);
    std::vector<std::string> certSignatures;
    if (!VerifyHapOpensslUtils::GetSignatures(pkcs7Context.certChains[0], certSignatures)) {
        SIGNATURE_TOOLS_LOGE("Get sianatures failed");
        return GET_SIGNATURE_FAIL;
    }
    hapVerifyV1Result.SetSignature(certSignatures);
    return VERIFY_SUCCESS;
}

int32_t VerifyHap::WriteVerifyOutput(Pkcs7Context& pkcs7Context, Options* options)
{
    bool flag = VerifyHap::HapOutPutCertChain(pkcs7Context.certChains[0],
        options->GetString(Options::OUT_CERT_CHAIN));
    if (!flag) {
        SIGNATURE_TOOLS_LOGE("out put cert chain failed");
        return OUT_PUT_FILE_FAIL;
    }
    flag = VerifyHap::HapOutPutPkcs7(pkcs7Context.p7, options->GetString(Options::OUT_PROFILE));
    if (!flag) {
        SIGNATURE_TOOLS_LOGE("out put p7b failed");
        return OUT_PUT_FILE_FAIL;
    }
    return VERIFY_SUCCESS;
}
} // namespace SignatureTools
} // namespace OHOS