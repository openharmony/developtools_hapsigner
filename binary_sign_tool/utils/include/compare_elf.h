/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef SIGNATURETOOLS_COMPARE_ELF_H
#define SIGNATURETOOLS_COMPARE_ELF_H

#include <string>
#include <elfio.hpp>

#include "signature_tools_log.h"

namespace OHOS {
namespace SignatureTools {

class CompareElf {
public:
    CompareElf(const std::string& originalFilePath, const std::string& savedFilePath);
    ~CompareElf();

    bool Validate();

private:
    bool ValidateBeforeShstrtabUnchange(int shstrtabIndex);
    bool ValidateShstrtabSizeChange(int shstrtabIndex);
    bool ValidateSegmentsBeforeShstrtab(int shstrtabIndex);
    bool ValidateSegmentsAfterShstrtab(int shstrtabIndex);
    bool ValidateAfterShstrtabSections(int shstrtabIndex);
    static std::string BuildSectionInfo(ELFIO::section* section);
    static std::string BuildSegmentInfo(ELFIO::segment* segment);

    static constexpr const char* CODE_SIGN_SEC_NAME = ".codesign";
    static constexpr const char* PERMISSION_SEC_NAME = ".permission";
    static constexpr const char* PROFILE_SEC_NAME = ".profile";

    std::string originalFilePath_;
    std::string savedFilePath_;
    ELFIO::elfio originalElf_;
    ELFIO::elfio savedElf_;
};

} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATURETOOLS_COMPARE_ELF_H
