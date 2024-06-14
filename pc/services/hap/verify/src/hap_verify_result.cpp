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
    : version(0), publicKeys(), signatures(), pkcs7SignBlock(),
    pkcs7ProfileBlock(), optionalBlocks(), provisionInfo()
{
}

HapVerifyResult::~HapVerifyResult()
{
}

int32_t HapVerifyResult::GetVersion() const
{
    return version;
}

void HapVerifyResult::SetVersion(int32_t signatureVersion)
{
    version = signatureVersion;
}

void HapVerifyResult::SetPkcs7SignBlock(const ByteBuffer& pkcs7)
{
    pkcs7SignBlock = pkcs7;
}

void HapVerifyResult::SetPkcs7ProfileBlock(const ByteBuffer& pkcs7)
{
    pkcs7ProfileBlock = pkcs7;
}

void HapVerifyResult::SetOptionalBlocks(const std::vector<OptionalBlock>& option)
{
    optionalBlocks = option;
}

std::vector<std::string> HapVerifyResult::GetPublicKey() const
{
    return publicKeys;
}

std::vector<std::string> HapVerifyResult::GetSignature() const
{
    return signatures;
}

void HapVerifyResult::SetPublicKey(const std::vector<std::string>& inputPubkeys)
{
    publicKeys = inputPubkeys;
}

void HapVerifyResult::SetSignature(const std::vector<std::string>& inputSignatures)
{
    signatures = inputSignatures;
}

int32_t HapVerifyResult::GetProperty(std::string& property) const
{
    return GetBlockFromOptionalBlocks(PROPERTY_BLOB, property);
}

int32_t HapVerifyResult::GetBlockFromOptionalBlocks(int32_t blockType, std::string& block) const
{
    for (unsigned long i = 0; i < optionalBlocks.size(); i++) {
        if (optionalBlocks[i].optionalType == blockType) {
            const ByteBuffer& option = optionalBlocks[i].optionalBlockValue;
            block += std::string(option.GetBufferPtr(), option.GetCapacity());
            return GET_SUCCESS;
        }
    }
    return NO_THIS_BLOCK_IN_PACKAGE;
}

void HapVerifyResult::SetProvisionInfo(const ProfileInfo& info)
{
    provisionInfo = info;
}

ProfileInfo HapVerifyResult::GetProvisionInfo() const
{
    return provisionInfo;
}

std::vector<int8_t> HapVerifyResult::GetProfile() const
{
    return profile;
}

void HapVerifyResult::SetProfile(std::vector<int8_t> profile)
{
    this->profile = profile;
}
} // namespace SignatureTools
} // namespace OHOS