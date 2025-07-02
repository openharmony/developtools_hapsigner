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

#ifndef SIGNATRUETOOLS_VERIFY_ELF_H
#define SIGNATRUETOOLS_VERIFY_ELF_H

#include <string>
#include <vector>
#include <elfio.hpp>

#include "options.h"
#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {

struct ElfSignInfo {
    uint32_t type;
    uint32_t length;
    uint8_t  version;
    uint8_t  hashAlgorithm;
    uint8_t  logBlockSize;
    uint8_t  saltSize;
    uint32_t signSize;
    uint64_t dataSize;
    uint8_t  rootHash[64];
    uint8_t  salt[32];
    uint32_t flags;
    uint8_t  reserved_1[12];
    uint8_t  reserved_2[127];
    uint8_t  csVersion;
    uint8_t  signature[0];
};

class VerifyElf {
public:
    static constexpr int PAGE_SIZE = 4096;
    static const int8_t SIGNATURE_BLOCK;
    static const int8_t PROFILE_NOSIGNED_BLOCK;
    static const int8_t PROFILE_SIGNED_BLOCK;
    static const int8_t KEY_ROTATION_BLOCK;
    static const int8_t CODESIGNING_BLOCK_TYPE;
    static const std::string profileSec;
    static const std::string permissionSec;
    static const std::string codesignSec;

public:
    bool Verify(Options* options);
    static bool CheckParams(Options* options);
    static bool GetRawContent(const std::vector<int8_t>& contentVec, std::string& rawContent);

private:
    static bool ParseSignBlock(const ELFIO::elfio& elfReader);
};
} // namespace SignatureTools
} // namespace OHOS
#endif