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
#ifndef SIGNATRUETOOLS_VERIFY_HAP_V2_H
#define SIGNATRUETOOLS_VERIFY_HAP_V2_H
#include <string>

#include "byte_buffer.h"
#include "random_access_file.h"
#include "hap_verify_result.h"
#include "profile_verify.h"
#include "verify_hap_openssl_utils.h"
#include "signature_info.h"
#include "options.h"
#include "file_utils.h"

namespace OHOS {
namespace SignatureTools {
class VerifyHap {
public:
    int32_t Verify(const std::string& filePath, HapVerifyResult& hapVerifyV1Result, Options* options);

    DLL_EXPORT bool CheckFilePath(const std::string& filePath, std::string& standardFilePath);
    static bool HapOutPutPkcs7(PKCS7* p7, const std::string& outPutPath);
    static bool HapOutPutCertChain(std::vector<X509*>& certs, const std::string& outPutPath);
    int32_t VerifyElfProfile(std::vector<int8_t>& profileData, HapVerifyResult& hapVerifyV1Result,
                             Options* options, Pkcs7Context& pkcs7Context);
    int32_t WriteVerifyOutput(Pkcs7Context& pkcs7Context, Options* options);
    int32_t InithapVerify(RandomAccessFile& hapFile, const std::string& filePath,
                          SignatureInfo& hapSignInfo, HapVerifyResult& hapVerifyV1Result);
    int32_t Verify(RandomAccessFile& hapFile, HapVerifyResult& hapVerifyV1Result, Options* options,
                   const std::string& filePath);
    bool CheckCodeSign(const std::string& hapFilePath, const std::vector<OptionalBlock>& optionalBlocks)const;
    static int GetProfileContent(const std::string profile, std::string& ret);
    bool VerifyAppSourceAndParseProfile(Pkcs7Context& pkcs7Context, const ByteBuffer& hapProfileBlock,
                                        HapVerifyResult& hapVerifyV1Result, bool& profileNeadWriteCrl);
    bool VerifyAppPkcs7(Pkcs7Context& pkcs7Context, const ByteBuffer& hapSignatureBlock);
    DLL_EXPORT bool GetDigestAndAlgorithm(Pkcs7Context& digest);
    DLL_EXPORT bool ParseAndVerifyProfileIfNeed(const std::string& profile, ProfileInfo& provisionInfo,
                                                bool isCallParseAndVerify);
    bool IsAppDistributedTypeAllowInstall(const AppDistType& type, const ProfileInfo& provisionInfo) const;
    DLL_EXPORT bool VerifyProfileInfo(const Pkcs7Context& pkcs7Context, const Pkcs7Context& profileContext,
                                      ProfileInfo& provisionInfo);
    DLL_EXPORT bool GenerateAppId(ProfileInfo& provisionInfo);
    DLL_EXPORT bool GenerateFingerprint(ProfileInfo& provisionInfo);
    bool VerifyProfileSignature(const Pkcs7Context& pkcs7Context, Pkcs7Context& profileContext);
    void SetProfileBlockData(const Pkcs7Context& pkcs7Context, const ByteBuffer& hapProfileBlock,
                             ProfileInfo& provisionInfo);
    void SetOrganization(ProfileInfo& provisionInfo);
    bool NeedParseJson(const ByteBuffer& buffer);
    static const int32_t HEX_PRINT_LENGTH;
    static const int32_t DIGEST_BLOCK_LEN_OFFSET;
    static const int32_t DIGEST_ALGORITHM_OFFSET;
    static const int32_t DIGEST_LEN_OFFSET;
    static const int32_t DIGEST_OFFSET_IN_CONTENT;
    static const std::string HAP_APP_PATTERN;
    static const std::string HQF_APP_PATTERN;
    static const std::string HSP_APP_PATTERN;
    static const std::string APP_APP_PATTERN;
    static const int OFFSET_ZERO = 0;
    static const int OFFSET_FOUR = 4;
    static const int OFFSET_EIGHT = 8;

};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_VERIFY_HAP_V2_H