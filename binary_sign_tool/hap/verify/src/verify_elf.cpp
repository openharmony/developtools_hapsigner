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

#include "verify_elf.h"

#include <fstream>
#include "constant.h"
#include "file_utils.h"
#include "signature_tools_log.h"
#include "hash_utils.h"
#include "pkcs7_data.h"

namespace OHOS {
namespace SignatureTools {

const int8_t VerifyElf::SIGNATURE_BLOCK = 0;
const int8_t VerifyElf::PROFILE_NOSIGNED_BLOCK = 1;
const int8_t VerifyElf::PROFILE_SIGNED_BLOCK = 2;
const int8_t VerifyElf::KEY_ROTATION_BLOCK = 3;
const int8_t VerifyElf::CODESIGNING_BLOCK_TYPE = 3;
const std::string VerifyElf::codesignSec = ".codesign";
const std::string VerifyElf::profileSec = ".profile";
const std::string VerifyElf::permissionSec = ".permission";

bool VerifyElf::Verify(Options* options)
{
    // check param
    if (options == nullptr) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "Param options is null.");
        return false;
    }
    std::string elfFile = options->GetString(Options::IN_FILE);
    ELFIO::elfio elfReader;
    if (!elfReader.load(elfFile)) {
        SIGNATURE_TOOLS_LOGE("failed to load input ELF file");
        return false;
    }


    // get codesignSec section

    ParseSignBlock(elfReader);

    // get profileSec section



    // get permissionSec section

    return true;
}

bool VerifyElf::ParseSignBlock(const ELFIO::elfio& elfReader)
{
    ELFIO::section* sec = elfReader.sections[codesignSec];
    if (!sec) {
        SIGNATURE_TOOLS_LOGE("codesign section is not found");
        return false;
    }
    ELFIO::Elf64_Off secOffElf64 = sec->get_offset();
    uint64_t secOff = static_cast<uint64_t>(secOffElf64);
    if (secOff % PAGE_SIZE != 0) {
        SIGNATURE_TOOLS_LOGE("codesign section offset is not aligned");
        return false;
    }
    const char* data = sec->get_data();
    uint64_t csBlockSize = sec->get_size();
    if (csBlockSize == 0 || csBlockSize % PAGE_SIZE != 0) {
        SIGNATURE_TOOLS_LOGE("codesign section size is not aligned");
        return false;
    }
    const ElfSignInfo* signInfo = reinterpret_cast<const ElfSignInfo*>(data);
    PrintMsg("codesign section offset: " + std::to_string(signInfo->dataSize));
    return true;
}

bool VerifyElf::GetRawContent(const std::vector<int8_t>& contentVec, std::string& rawContent)
{
    PKCS7Data p7Data;
    int parseFlag = p7Data.Parse(contentVec);
    if (parseFlag < 0) {
        SIGNATURE_TOOLS_LOGE("parse content failed!");
        return false;
    }
    int verifyFlag = p7Data.Verify();
    if (verifyFlag < 0) {
        SIGNATURE_TOOLS_LOGE("verify content failed!");
        return false;
    }
    int getContentFlag = p7Data.GetContent(rawContent);
    if (getContentFlag < 0) {
        SIGNATURE_TOOLS_LOGE("get p7Data raw content failed!");
        return false;
    }
    return true;
}

} // namespace SignatureTools
} // namespace OHOS