/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef SIGNATURETOOLS_CODE_SIGNING_H
#define SIGNATURETOOLS_CODE_SIGNING_H

#include <vector>
#include <string>
#include <mutex>

#include "securec.h"
#include "thread_pool.h"
#include "file_utils.h"
#include "local_signer.h"
#include "signer_config.h"
#include "signature_tools_log.h"
#include "fs_verity_generator.h"
#include "bc_signeddata_generator.h"

namespace OHOS {
namespace SignatureTools {
class CodeSigning {
public:
    CodeSigning(SignerConfig* signConfig, bool adHoc);
    CodeSigning();

    bool GetElfCodeSignBlock(const std::string &input, uint64_t& csOffset, std::vector<int8_t> &codesignData);

public:
    bool GenerateSignature(const std::vector<int8_t>& signedData, const std::string& ownerID,
                           std::vector<int8_t>& ret);
    bool GetOwnerIdFromCert(std::string& ownerID);
    SignerConfig* m_signConfig;
    bool m_adHoc;

private:
    static constexpr int MIN_CERT_CHAIN_SIZE = 2;
    static constexpr int MAX_CERT_CHAIN_SIZE = 3;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATURETOOLS_CODE_SIGNING_H