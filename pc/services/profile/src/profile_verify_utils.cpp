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
#include "profile_verify_utils.h"
#include "signature_tools_log.h"
#include "matching_result.h"
#include "cert_verify_openssl_utils.h"
#include "signing_block_utils.h"
#include "verify_openssl_utils.h"
namespace OHOS {
    namespace SignatureTools {
        bool HapProfileVerifyUtils::ParseProfile(Pkcs7Context& profilePkcs7Context,
                                                 const Pkcs7Context& hapPkcs7Context,
                                                 const ByteBuffer& pkcs7ProfileBlock, std::string& profile)
        {
            if (hapPkcs7Context.matchResult.matchState == MATCH_WITH_SIGN &&
                hapPkcs7Context.matchResult.source == APP_GALLARY) {
                profile = std::string(pkcs7ProfileBlock.GetBufferPtr(), pkcs7ProfileBlock.GetCapacity());
                    SIGNATURE_TOOLS_LOGD("hap include unsigned provision");
                    return true;
            }
            const unsigned char* pkcs7Block = reinterpret_cast<const unsigned char*>(
            pkcs7ProfileBlock.GetBufferPtr());
            uint32_t pkcs7Len = static_cast<unsigned int>(pkcs7ProfileBlock.GetCapacity());
            if (!HapVerifyOpensslUtils::ParsePkcs7Package(pkcs7Block, pkcs7Len, profilePkcs7Context)) {
                SIGNATURE_TOOLS_LOGE("parse pkcs7 failed");
                return false;
            }
            profile = std::string(profilePkcs7Context.content.GetBufferPtr(),
            profilePkcs7Context.content.GetCapacity());
            return true;
        }
        bool HapProfileVerifyUtils::VerifyProfile(Pkcs7Context& pkcs7Context)
        {
            if (!HapVerifyOpensslUtils::GetCertChains(pkcs7Context.p7, pkcs7Context)) {
                SIGNATURE_TOOLS_LOGE("GetCertChains from pkcs7 failed");
                return false;
            }
                if (!HapVerifyOpensslUtils::VerifyPkcs7(pkcs7Context)) {
                SIGNATURE_TOOLS_LOGE("verify profile signature failed");
                return false;
            }
            return true;
        }
    }
} // namespace OHOS