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
#include "hap_signer_block_utils.h"
#include "hap_verify_result.h"

namespace OHOS {
namespace SignatureTools {
HapVerifyResult::HapVerifyResult()
    : m_version(0), m_publicKeys(), m_signatures(), m_pkcs7SignBlock(),
    m_pkcs7ProfileBlock(), m_optionalBlocks(), m_provisionInfo()
{
}

void HapVerifyResult::SetPkcs7SignBlock(const ByteBuffer& pkcs7)
{
    m_pkcs7SignBlock = pkcs7;
}

void HapVerifyResult::SetPkcs7ProfileBlock(const ByteBuffer& pkcs7)
{
    m_pkcs7ProfileBlock = pkcs7;
}

void HapVerifyResult::SetOptionalBlocks(const std::vector<OptionalBlock>& option)
{
    m_optionalBlocks = option;
}

int32_t HapVerifyResult::GetVersion() const
{
    return m_version;
}

void HapVerifyResult::SetVersion(int32_t signatureVersion)
{
    m_version = signatureVersion;
}

std::vector<std::string> HapVerifyResult::GetPublicKey() const
{
    return m_publicKeys;
}

std::vector<std::string> HapVerifyResult::GetSignature() const
{
    return m_signatures;
}

void HapVerifyResult::SetPublicKey(const std::vector<std::string>& inputPubkeys)
{
    m_publicKeys = inputPubkeys;
}

void HapVerifyResult::SetSignature(const std::vector<std::string>& inputSignatures)
{
    m_signatures = inputSignatures;
}

int32_t HapVerifyResult::GetProperty(std::string& property) const
{
    return GetBlockFromOptionalBlocks(PROPERTY_BLOB, property);
}

int32_t HapVerifyResult::GetBlockFromOptionalBlocks(int32_t blockType, std::string& block) const
{
    for (unsigned long i = 0; i < m_optionalBlocks.size(); i++) {
        if (m_optionalBlocks[i].optionalType == blockType) {
            const ByteBuffer& option = m_optionalBlocks[i].optionalBlockValue;
            block += std::string(option.GetBufferPtr(), option.GetCapacity());
            return GET_SUCCESS;
        }
    }
    return NO_THIS_BLOCK_IN_PACKAGE;
}

void HapVerifyResult::SetProvisionInfo(const ProfileInfo& info)
{
    m_provisionInfo = info;
}

ProfileInfo HapVerifyResult::GetProvisionInfo() const
{
    return m_provisionInfo;
}

std::vector<int8_t> HapVerifyResult::GetProfile() const
{
    return m_profile;
}

void HapVerifyResult::SetProfile(std::vector<int8_t> profile)
{
    this->m_profile = profile;
}
} // namespace SignatureTools
} // namespace OHOS