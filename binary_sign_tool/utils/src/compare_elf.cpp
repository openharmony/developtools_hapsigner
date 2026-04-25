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

#include "compare_elf.h"
#include <securec.h>

namespace OHOS {
namespace SignatureTools {

CompareElf::CompareElf(const std::string& originalFilePath, const std::string& savedFilePath)
    : originalFilePath_(originalFilePath), savedFilePath_(savedFilePath)
{
}

CompareElf::~CompareElf()
{
}

bool CompareElf::Validate()
{
    // Load the original ELF file
    if (!originalElf_.load(originalFilePath_)) {
        SIGNATURE_TOOLS_LOGW("[CompareElf] Failed to load original ELF file: %s", originalFilePath_.c_str());
        return false;
    }

    // Load the saved ELF file
    if (!savedElf_.load(savedFilePath_)) {
        SIGNATURE_TOOLS_LOGW("[CompareElf] Failed to load saved ELF file: %s", savedFilePath_.c_str());
        return false;
    }

    // Get .shstrtab index from original elfio
    int origShstrtabIndex = originalElf_.get_section_name_str_index();
    // Get .shstrtab index in saved file
    int savedShstrtabIndex = savedElf_.get_section_name_str_index();
    // Validate section count before .shstrtab is the same
    if (origShstrtabIndex != savedShstrtabIndex) {
        SIGNATURE_TOOLS_LOGW("[CompareElf] .shstrtab index mismatch: original=%d, saved=%d",
                             origShstrtabIndex, savedShstrtabIndex);
        return false;
    }

    // Validate each section before .shstrtab remains unchanged
    if (!ValidateBeforeShstrtabUnchange(origShstrtabIndex)) {
        SIGNATURE_TOOLS_LOGW("[CompareElf] sections before .shstrtab changed");
    }

    // Validate .shstrtab size change based on section existence
    if (!ValidateShstrtabSizeChange(origShstrtabIndex)) {
        SIGNATURE_TOOLS_LOGW("[CompareElf] .shstrtab size changed");
    }

    // Validate sections after .shstrtab have correct offset shift
    if (!ValidateAfterShstrtabSections(origShstrtabIndex)) {
        SIGNATURE_TOOLS_LOGW("[CompareElf] sections after .shstrtab changed");
    }

    // Validate segments before .shstrtab remain unchanged
    if (!ValidateSegmentsBeforeShstrtab(origShstrtabIndex)) {
        SIGNATURE_TOOLS_LOGW("[CompareElf] segments before .shstrtab changed");
    }

    // Validate segments after .shstrtab have correct offset shift
    if (!ValidateSegmentsAfterShstrtab(origShstrtabIndex)) {
        SIGNATURE_TOOLS_LOGW("[CompareElf] segments after .shstrtab changed");
    }

    return true;
}

bool CompareElf::ValidateBeforeShstrtabUnchange(int shstrtabIndex)
{
    for (int i = 0; i < shstrtabIndex; i++) {
        ELFIO::section* origSec = originalElf_.sections[i];
        ELFIO::section* savedSec = savedElf_.sections[i];

        if (!origSec || !savedSec) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Section %d is null", i);
            return false;
        }

        if (origSec->get_name() != savedSec->get_name() || origSec->get_type() != savedSec->get_type() ||
            origSec->get_flags() != savedSec->get_flags() || origSec->get_address() != savedSec->get_address() ||
            origSec->get_offset() != savedSec->get_offset() || origSec->get_size() != savedSec->get_size() ||
            origSec->get_link() != savedSec->get_link() || origSec->get_info() != savedSec->get_info() ||
            origSec->get_addr_align() != savedSec->get_addr_align() ||
            origSec->get_entry_size() != savedSec->get_entry_size()) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Section %s information changed (before .shstrtab)",
                origSec->get_name().c_str());
            SIGNATURE_TOOLS_LOGW("[CompareElf] Original %s", BuildSectionInfo(origSec).c_str());
            SIGNATURE_TOOLS_LOGW("[CompareElf] Saved %s", BuildSectionInfo(savedSec).c_str());
        }
    }
    return true;
}

bool CompareElf::ValidateShstrtabSizeChange(int shstrtabIndex)
{
    ELFIO::section* origShstrtab = originalElf_.sections[shstrtabIndex];
    ELFIO::section* savedShstrtab = savedElf_.sections[shstrtabIndex];

    if (!origShstrtab || !savedShstrtab) {
        SIGNATURE_TOOLS_LOGW("[CompareElf] .shstrtab section is null");
        return false;
    }

    uint64_t origShstrtabSize = origShstrtab->get_size();
    uint64_t savedShstrtabSize = savedShstrtab->get_size();

    // Section name lengths (including null terminator)
    const size_t PROFILE_LEN = std::string(PROFILE_SEC_NAME).length() + 1;
    const size_t PERMISSION_LEN = std::string(PERMISSION_SEC_NAME).length() + 1;
    const size_t CODE_SIGN_LEN = std::string(CODE_SIGN_SEC_NAME).length() + 1;

    // Check existence of sections in both files
    bool origHasProfile = (originalElf_.sections[PROFILE_SEC_NAME] != nullptr);
    bool origHasPermission = (originalElf_.sections[PERMISSION_SEC_NAME] != nullptr);
    bool origHasCodeSign = (originalElf_.sections[CODE_SIGN_SEC_NAME] != nullptr);

    bool savedHasProfile = (savedElf_.sections[PROFILE_SEC_NAME] != nullptr);
    bool savedHasPermission = (savedElf_.sections[PERMISSION_SEC_NAME] != nullptr);
    bool savedHasCodeSign = (savedElf_.sections[CODE_SIGN_SEC_NAME] != nullptr);

    // Calculate expected size change based on section existence changes
    int64_t expectedIncrement = 0;
    if (savedHasProfile && !origHasProfile) {
        expectedIncrement += PROFILE_LEN;
    } else if (!savedHasProfile && origHasProfile) {
        expectedIncrement -= PROFILE_LEN;
    }

    if (savedHasPermission && !origHasPermission) {
        expectedIncrement += PERMISSION_LEN;
    } else if (!savedHasPermission && origHasPermission) {
        expectedIncrement -= PERMISSION_LEN;
    }

    if (savedHasCodeSign && !origHasCodeSign) {
        expectedIncrement += CODE_SIGN_LEN;
    } else if (!savedHasCodeSign && origHasCodeSign) {
        expectedIncrement -= CODE_SIGN_LEN;
    }

    // Calculate actual increment
    int64_t actualIncrement = static_cast<int64_t>(savedShstrtabSize) - static_cast<int64_t>(origShstrtabSize);

    if (actualIncrement != expectedIncrement) {
        SIGNATURE_TOOLS_LOGW("[CompareElf] .shstrtab size change mismatch: expected=%ld, actual=%ld",
                             expectedIncrement, actualIncrement);
        return false;
    }
    return true;
}

bool CompareElf::ValidateSegmentsBeforeShstrtab(int shstrtabIndex)
{
    ELFIO::section* origShstrtab = originalElf_.sections[shstrtabIndex];
    uint64_t shstrtabOffset = origShstrtab->get_offset();

    // Validate all segments whose file offset is before .shstrtab
    int segmentCount = static_cast<int>(originalElf_.segments.size());
    int savedSegmentCount = static_cast<int>(savedElf_.segments.size());
    if (segmentCount != savedSegmentCount) {
        SIGNATURE_TOOLS_LOGW("[CompareElf] Segment count mismatch: original=%d, saved=%d",
                             segmentCount, savedSegmentCount);
        return false;
    }

    for (int i = 0; i < segmentCount; i++) {
        ELFIO::segment* origSeg = originalElf_.segments[i];
        ELFIO::segment* savedSeg = savedElf_.segments[i];

        if (!origSeg || !savedSeg) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Segment %d is null", i);
            return false;
        }

        // Only validate segments that are located before .shstrtab in the file
        uint64_t origOffset = origSeg->get_offset();
        if (origOffset >= shstrtabOffset) {
            continue;
        }

        // Validate segment properties
        if (origSeg->get_type() != savedSeg->get_type() || origSeg->get_flags() != savedSeg->get_flags() ||
            origSeg->get_virtual_address() != savedSeg->get_virtual_address() ||
            origSeg->get_physical_address() != savedSeg->get_physical_address() ||
            origSeg->get_offset() != savedSeg->get_offset() ||
            origSeg->get_file_size() != savedSeg->get_file_size() ||
            origSeg->get_memory_size() != savedSeg->get_memory_size() ||
            origSeg->get_align() != savedSeg->get_align()) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Segment %d properties changed (before .shstrtab)", i);
            SIGNATURE_TOOLS_LOGW("[CompareElf] Original %s", BuildSegmentInfo(origSeg).c_str());
            SIGNATURE_TOOLS_LOGW("[CompareElf] Saved %s", BuildSegmentInfo(savedSeg).c_str());
        }
    }
    return true;
}

bool CompareElf::ValidateSegmentsAfterShstrtab(int shstrtabIndex)
{
    ELFIO::section* origShstrtab = originalElf_.sections[shstrtabIndex];
    ELFIO::section* savedShstrtab = savedElf_.sections[shstrtabIndex];

    uint64_t origShstrtabEnd = origShstrtab->get_offset() + origShstrtab->get_size();
    // Track expected offset: start from saved .shstrtab end
    uint64_t expectedOffset = savedShstrtab->get_offset() + savedShstrtab->get_size();

    int segmentCount = static_cast<int>(originalElf_.segments.size());
    int savedSegmentCount = static_cast<int>(savedElf_.segments.size());
    if (segmentCount != savedSegmentCount) {
        SIGNATURE_TOOLS_LOGW("[CompareElf] Segment count mismatch: original=%d, saved=%d",
                             segmentCount, savedSegmentCount);
        return false;
    }

    for (int i = 0; i < segmentCount; i++) {
        ELFIO::segment* origSeg = originalElf_.segments[i];
        ELFIO::segment* savedSeg = savedElf_.segments[i];

        // Only validate segments whose original file offset is after .shstrtab
        uint64_t origOffset = origSeg->get_offset();
        if (origOffset < origShstrtabEnd) {
            continue;
        }

        // File size and memory size must remain unchanged
        if (origSeg->get_file_size() != savedSeg->get_file_size()) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Segment %d file size changed after .shstrtab: original=%lu, saved=%lu",
                                 i, origSeg->get_file_size(), savedSeg->get_file_size());
        }
        if (origSeg->get_memory_size() != savedSeg->get_memory_size()) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Segment %d memory size changed after .shstrtab: original=%lu, saved=%lu",
                                 i, origSeg->get_memory_size(), savedSeg->get_memory_size());
        }

        // Calculate expected offset considering alignment
        uint64_t align = origSeg->get_align();
        if (align > 1) {
            expectedOffset = (expectedOffset + align - 1) / align * align;
        }

        // Offset must match expected value
        if (savedSeg->get_offset() != expectedOffset) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Segment %d offset mismatch: expected=%lu, actual=%lu, align=%lu",
                                 i, expectedOffset, savedSeg->get_offset(), align);
        }

        // Other properties must remain unchanged
        if (origSeg->get_type() != savedSeg->get_type() || origSeg->get_flags() != savedSeg->get_flags() ||
            origSeg->get_virtual_address() != savedSeg->get_virtual_address() ||
            origSeg->get_physical_address() != savedSeg->get_physical_address() ||
            origSeg->get_align() != savedSeg->get_align()) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Segment %d properties changed after .shstrtab", i);
            SIGNATURE_TOOLS_LOGW("[CompareElf] Original %s", BuildSegmentInfo(origSeg).c_str());
            SIGNATURE_TOOLS_LOGW("[CompareElf] Saved %s", BuildSegmentInfo(savedSeg).c_str());
        }

        // Advance expected offset by this segment's file size
        expectedOffset += savedSeg->get_file_size();
    }

    return true;
}

bool CompareElf::ValidateAfterShstrtabSections(int shstrtabIndex)
{
    ELFIO::section* origShstrtab = originalElf_.sections[shstrtabIndex];
    ELFIO::section* savedShstrtab = savedElf_.sections[shstrtabIndex];

    uint64_t origShstrtabEnd = origShstrtab->get_offset() + origShstrtab->get_size();
    // Track expected offset: start from saved .shstrtab end
    uint64_t expectedOffset = savedShstrtab->get_offset() + savedShstrtab->get_size();

    int savedSectionsCount = static_cast<int>(savedElf_.sections.size());
    for (int i = shstrtabIndex + 1; i < savedSectionsCount; i++) {
        ELFIO::section* savedSec = savedElf_.sections[i];
        if (!savedSec) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Saved section %d is null", i);
            return false;
        }

        // Skip signing sections (.profile, .permission, .codesign)
        std::string secName = savedSec->get_name();
        if (secName == CODE_SIGN_SEC_NAME || secName == PERMISSION_SEC_NAME || secName == PROFILE_SEC_NAME) {
            break;
        }

        ELFIO::section* origSec = originalElf_.sections[i];
        if (!origSec) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Original section %d is null", i);
            return false;
        }

        // Only validate sections whose original offset is after .shstrtab
        if (origSec->get_offset() < origShstrtabEnd) {
            continue;
        }

        // Size must remain unchanged
        if (origSec->get_size() != savedSec->get_size()) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Section %s size changed after .shstrtab: original=%lu, saved=%lu",
                                 secName.c_str(), origSec->get_size(), savedSec->get_size());
            return false;
        }

        // Calculate expected offset considering alignment
        uint64_t addrAlign = origSec->get_addr_align();
        if (addrAlign > 1) {
            expectedOffset = (expectedOffset + addrAlign - 1) / addrAlign * addrAlign;
        }

        // Offset must match expected value
        if (savedSec->get_offset() != expectedOffset) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Section %s offset mismatch: expected=%lu, actual=%lu, align=%lu",
                                 secName.c_str(), expectedOffset, savedSec->get_offset(), addrAlign);
        }

        // Other fields must remain unchanged
        if (origSec->get_type() != savedSec->get_type() || origSec->get_flags() != savedSec->get_flags() ||
            origSec->get_address() != savedSec->get_address() || origSec->get_link() != savedSec->get_link() ||
            origSec->get_info() != savedSec->get_info() || origSec->get_addr_align() != savedSec->get_addr_align() ||
            origSec->get_entry_size() != savedSec->get_entry_size()) {
            SIGNATURE_TOOLS_LOGW("[CompareElf] Section %s properties changed after .shstrtab", secName.c_str());
            SIGNATURE_TOOLS_LOGW("[CompareElf] Original %s", BuildSectionInfo(origSec).c_str());
            SIGNATURE_TOOLS_LOGW("[CompareElf] Saved %s", BuildSectionInfo(savedSec).c_str());
        }

        // Advance expected offset by this section's data size
        expectedOffset += savedSec->get_size();
    }

    return true;
}

std::string CompareElf::BuildSectionInfo(ELFIO::section* section)
{
    if (!section) {
        return "Section is null";
    }
    char buf[512];
    int ret = snprintf_s(buf, sizeof(buf), sizeof(buf) - 1,
        "Section[name=%s, type=0x%x, flags=0x%llx, address=0x%llx, offset=0x%llx, size=0x%llx,"
        " link=0x%x, info=0x%x, addrAlign=0x%llx, entSize=0x%llx]",
        section->get_name().c_str(),
        section->get_type(),
        static_cast<unsigned long long>(section->get_flags()),
        static_cast<unsigned long long>(section->get_address()),
        static_cast<unsigned long long>(section->get_offset()),
        static_cast<unsigned long long>(section->get_size()),
        section->get_link(),
        section->get_info(),
        static_cast<unsigned long long>(section->get_addr_align()),
        static_cast<unsigned long long>(section->get_entry_size()));
    if (ret < 0) {
        return "Section[format error]";
    }
    return std::string(buf);
}

std::string CompareElf::BuildSegmentInfo(ELFIO::segment* segment)
{
    if (!segment) {
        return "Segment is null";
    }
    char buf[512];
    int ret = snprintf_s(buf, sizeof(buf), sizeof(buf) - 1,
        "Segment[type=0x%x, flags=0x%x, vaddr=0x%llx, paddr=0x%llx, offset=0x%llx, filesz=0x%llx,"
        " memsz=0x%llx, align=0x%llx]",
        segment->get_type(),
        segment->get_flags(),
        static_cast<unsigned long long>(segment->get_virtual_address()),
        static_cast<unsigned long long>(segment->get_physical_address()),
        static_cast<unsigned long long>(segment->get_offset()),
        static_cast<unsigned long long>(segment->get_file_size()),
        static_cast<unsigned long long>(segment->get_memory_size()),
        static_cast<unsigned long long>(segment->get_align()));
    if (ret < 0) {
        return "Segment[format error]";
    }
    return std::string(buf);
}
} // namespace SignatureTools
} // namespace OHOS
