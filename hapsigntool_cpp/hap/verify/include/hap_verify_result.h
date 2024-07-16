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
#ifndef SIGNATRUETOOLS_VERIFY_RESULT_H
#define SIGNATRUETOOLS_VERIFY_RESULT_H
#include <string>
#include <vector>

#include "export_define.h"
#include "byte_buffer.h"
#include "profile_info.h"

namespace OHOS {
namespace SignatureTools {
enum class ModeDev {
    DEFAULT = 0,
    DEV,
    NON_DEV,
};

enum VerifyHapResultCode {
    VERIFY_SUCCESS = 0,
    FILE_PATH_INVALID = -1,
    OPEN_FILE_ERROR = -2,
    SIGNATURE_NOT_FOUND = -3,
    GET_DIGEST_FAIL = -4,
    NO_PROFILE_BLOCK_FAIL = -5,
    VERIFY_SIGNATURE_FAIL = -6,
    VERIFY_SOURCE_INIT_FAIL = -7,
    VERIFY_INTEGRITY_FAIL = -8,
    FILE_SIZE_TOO_LARGE = -9,
    GET_PUBLICKEY_FAIL = -10,
    VERIFY_APP_PKCS7_FAIL = -11,
    PROFILE_PARSE_FAIL = -12,
    APP_SOURCE_NOT_TRUSTED = -13,
    GET_SIGNATURE_FAIL = -14,
    OUT_PUT_FILE_FAIL = -15,
    VERIFY_CODE_SIGN_FAIL = -16,
};

enum GetOptionalBlockResultCode {
    GET_SUCCESS = 0,
    NO_THIS_BLOCK_IN_PACKAGE = 1,
};

struct OptionalBlock {
    int32_t optionalType = 0;
    ByteBuffer optionalBlockValue;
};

class HapVerifyResult {
public:
    DLL_EXPORT HapVerifyResult();
    DLL_EXPORT ~HapVerifyResult() = default;
    DLL_EXPORT int32_t GetVersion() const;
    DLL_EXPORT void SetVersion(int32_t signatureVersion);
    DLL_EXPORT void SetPkcs7SignBlock(const ByteBuffer& pkcs7);
    DLL_EXPORT void SetPkcs7ProfileBlock(const ByteBuffer& pkcs7);
    DLL_EXPORT void SetOptionalBlocks(const std::vector<OptionalBlock>& option);
    DLL_EXPORT void SetProvisionInfo(const ProfileInfo& info);
    DLL_EXPORT int32_t GetProperty(std::string& property) const;
    DLL_EXPORT ProfileInfo GetProvisionInfo() const;
    DLL_EXPORT std::vector<std::string> GetPublicKey() const;
    DLL_EXPORT std::vector<std::string> GetSignature() const;
    DLL_EXPORT std::vector<int8_t> GetProfile() const;
    DLL_EXPORT void SetProfile(std::vector<int8_t> profile);
    void SetPublicKey(const std::vector<std::string>& inputPubkeys);
    void SetSignature(const std::vector<std::string>& inputSignatures);
    DLL_EXPORT int32_t GetBlockFromOptionalBlocks(int32_t blockType, std::string& block) const;

private:
    int32_t m_version = 0;
    std::vector<std::string> m_publicKeys;
    std::vector<std::string> m_signatures;
    ByteBuffer m_pkcs7SignBlock;
    ByteBuffer m_pkcs7ProfileBlock;
    std::vector<OptionalBlock> m_optionalBlocks;
    ProfileInfo m_provisionInfo;
    std::vector<int8_t> m_profile;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_VERIFY_RESULT_H
