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

package com.ohos.hapsigntool.utils;

import com.ohos.elfio.Elfio;
import com.ohos.elfio.Section;
import com.ohos.elfio.Segment;

import java.io.File;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.StandardOpenOption;

/**
 * Compare two ELF files to validate structural consistency after signing.
 * Validates sections and segments before/after .shstrtab remain correct.
 *
 * @since 2026/04/21
 */
public class CompareElf {
    /**
     * codesign section name
     */
    private static final String CODE_SIGN_SEC_NAME = ".codesign";

    /**
     * permission section name
     */
    private static final String PERMISSION_SEC_NAME = ".permission";

    /**
     * profile section name
     */
    private static final String PROFILE_SEC_NAME = ".profile";

    private static final LogUtils LOGGER = new LogUtils(CompareElf.class);

    private final File originalFile;

    private final File savedFile;

    private Elfio originalElf = new Elfio();

    private Elfio savedElf = new Elfio();

    /**
     * Constructor with two ELF files to compare.
     *
     * @param originalFile Original ELF file
     * @param savedFile Saved (modified) ELF file
     */
    public CompareElf(File originalFile, File savedFile) {
        this.originalFile = originalFile;
        this.savedFile = savedFile;
    }

    /**
     * Validate the saved ELF file against the original.
     *
     * @return true if validation passed
     * @throws IOException if file operations fail
     */
    public boolean validate() throws IOException {
        try (FileChannel inFc = FileChannel.open(originalFile.toPath(), StandardOpenOption.READ);
            FileChannel savedFc = FileChannel.open(savedFile.toPath(), StandardOpenOption.READ)) {
            if (!originalElf.load(inFc, true)) {
                LOGGER.warn("Failed to load original ELF file for validation: {}", originalFile.getPath());
                return false;
            }
            if (!savedElf.load(savedFc, true)) {
                LOGGER.warn("Failed to load saved ELF file for validation: {}", savedFile.getPath());
                return false;
            }

            // Get .shstrtab index from original elfio
            int origShstrtabIndex = originalElf.getSectionNameStrIndex();
            // Get .shstrtab index in saved file
            int savedShstrtabIndex = savedElf.getSectionNameStrIndex();
            // Validate section count before .shstrtab is same
            if (origShstrtabIndex != savedShstrtabIndex) {
                LOGGER.warn(".shstrtab index mismatch: original={}, saved={}", origShstrtabIndex, savedShstrtabIndex);
                return false;
            }

            // Validate each section before .shstrtab remains unchanged
            if (!validateBeforeShstrtabUnchange(origShstrtabIndex)) {
                LOGGER.warn("sections before .shstrtab changed");
            }

            // Validate .shstrtab size change based on section existence
            if (!validateShstrtabSizeChange(origShstrtabIndex)) {
                LOGGER.warn(".shstrtab size changed");
            }

            // Validate sections after .shstrtab (before signing sections) have correct offset shift
            if (!validateAfterShstrtabSections(origShstrtabIndex)) {
                LOGGER.warn("sections after .shstrtab changed");
            }

            // Validate segments before .shstrtab remain unchanged
            if (!validateSegmentsBeforeShstrtab(origShstrtabIndex)) {
                LOGGER.warn("segments before .shstrtab changed");
            }

            // Validate segments after .shstrtab have correct offset shift
            if (!validateSegmentsAfterShstrtab(origShstrtabIndex)) {
                LOGGER.warn("segments after .shstrtab changed");
            }

            return true;
        }
    }

    private boolean validateBeforeShstrtabUnchange(int shstrtabIndex) {

        for (int i = 0; i < shstrtabIndex; i++) {
            Section origSec = originalElf.getSection(i);
            Section savedSec = savedElf.getSection(i);

            if (origSec == null || savedSec == null) {
                LOGGER.warn("Section {} is null", i);
                return false;
            }

            if (!origSec.getName().equals(savedSec.getName()) || origSec.getType() != savedSec.getType()
                || origSec.getFlags() != savedSec.getFlags() || origSec.getAddress() != savedSec.getAddress()
                || origSec.getOffset() != savedSec.getOffset() || origSec.getSize() != savedSec.getSize()
                || origSec.getLink() != savedSec.getLink() || origSec.getInfo() != savedSec.getInfo()
                || origSec.getAddrAlign() != savedSec.getAddrAlign()
                || origSec.getEntSize() != savedSec.getEntSize()) {
                LOGGER.warn("Section {} information changed (before .shstrtab)", origSec.getName());
                LOGGER.warn("Original " + buildSectionInfo(origSec));
                LOGGER.warn("Saved " + buildSectionInfo(savedSec));
            }
        }
        return true;
    }

    /**
     * Validate .shstrtab size change based on section existence
     *
     * @param shstrtabIndex Index of .shstrtab section
     * @return true if validation passed
     */
    private boolean validateShstrtabSizeChange(int shstrtabIndex) {

        // Validate .shstrtab section
        Section origShstrtab = originalElf.getSection(shstrtabIndex);
        Section savedShstrtab = savedElf.getSection(shstrtabIndex);

        if (origShstrtab == null || savedShstrtab == null) {
            LOGGER.warn(".shstrtab section is null");
            return false;
        }

        // Get original and saved .shstrtab sizes and alignment
        long origShstrtabSize = origShstrtab.getSize();
        long savedShstrtabSize = savedShstrtab.getSize();

        int profileLen = PROFILE_SEC_NAME.length() + 1;
        int permissionLen = PERMISSION_SEC_NAME.length() + 1;
        int codeSignLen = CODE_SIGN_SEC_NAME.length() + 1;

        // Check existence of sections in both files
        boolean origHasProfile = originalElf.getSection(PROFILE_SEC_NAME) != null;
        boolean origHasPermission = originalElf.getSection(PERMISSION_SEC_NAME) != null;
        boolean origHasCodeSign = originalElf.getSection(CODE_SIGN_SEC_NAME) != null;

        boolean savedHasProfile = savedElf.getSection(PROFILE_SEC_NAME) != null;
        boolean savedHasPermission = savedElf.getSection(PERMISSION_SEC_NAME) != null;
        boolean savedHasCodeSign = savedElf.getSection(CODE_SIGN_SEC_NAME) != null;

        // Calculate expected size change based on section existence changes
        long expectedIncrement = 0L;
        if (savedHasProfile && !origHasProfile) {
            expectedIncrement += profileLen;
        } else if (!savedHasProfile && origHasProfile) {
            expectedIncrement -= profileLen;
        }

        if (savedHasPermission && !origHasPermission) {
            expectedIncrement += permissionLen;
        } else if (!savedHasPermission && origHasPermission) {
            expectedIncrement -= permissionLen;
        }

        if (savedHasCodeSign && !origHasCodeSign) {
            expectedIncrement += codeSignLen;
        } else if (!savedHasCodeSign && origHasCodeSign) {
            expectedIncrement -= codeSignLen;
        }

        // Calculate actual increment
        long actualIncrement = savedShstrtabSize - origShstrtabSize;

        if (actualIncrement != expectedIncrement) {
            LOGGER.warn(".shstrtab size change mismatch: expected=" + expectedIncrement + ", actual="
                + actualIncrement + ")");
            return false;
        }
        return true;
    }

    /**
     * Validate segments before .shstrtab section offset remain unchanged
     *
     * @param shstrtabIndex Offset of .shstrtab section
     */
    private boolean validateSegmentsBeforeShstrtab(int shstrtabIndex) {

        // Get .shstrtab offset for segment validation
        Section origShstrtab = originalElf.getSection(shstrtabIndex);
        long shstrtabOffset = origShstrtab.getOffset();

        // Validate all segments whose file offset is before .shstrtab
        int segmentCount = originalElf.getSegmentsCount();
        int savedSegmentCount = savedElf.getSegmentsCount();
        if (segmentCount != savedSegmentCount) {
            LOGGER.warn("Segment count mismatch: original={}, saved={}", segmentCount, savedSegmentCount);
            return false;
        }
        for (int i = 0; i < segmentCount; i++) {
            Segment origSeg = originalElf.getSegment(i);
            Segment savedSeg = savedElf.getSegment(i);

            if (origSeg == null || savedSeg == null) {
                LOGGER.warn("Segment {} is null", i);
                return false;
            }

            // Only validate segments that are located before .shstrtab in the file
            long origOffset = origSeg.getOffset();
            if (origOffset >= shstrtabOffset) {
                // This segment is at or after .shstrtab, skip validation
                continue;
            }

            // Validate segment properties
            if (origSeg.getType() != savedSeg.getType() || origSeg.getFlags() != savedSeg.getFlags()
                || origSeg.getVirtualAddress() != savedSeg.getVirtualAddress()
                || origSeg.getPhysicalAddress() != savedSeg.getPhysicalAddress()
                || origSeg.getOffset() != savedSeg.getOffset() || origSeg.getFileSize() != savedSeg.getFileSize()
                || origSeg.getMemorySize() != savedSeg.getMemorySize() || origSeg.getAlign() != savedSeg.getAlign()) {
                LOGGER.warn("Segment {} properties changed (before .shstrtab)", i);
                LOGGER.warn("Original " + buildSegmentInfo(origSeg));
                LOGGER.warn("Saved " + buildSegmentInfo(savedSeg));
            }
        }
        return true;
    }

    /**
     * Validate segments after .shstrtab have correct offset shift.
     * For segments whose file offset is after .shstrtab:
     * - File size and memory size must remain unchanged
     * - Offset must shift consistently considering alignment (chain-based calculation)
     * - Other properties (type, flags, vaddr, paddr, align) must remain unchanged
     *
     * @param shstrtabIndex Index of .shstrtab section
     * @return true if validation passed
     */
    private boolean validateSegmentsAfterShstrtab(int shstrtabIndex) {
        Section origShstrtab = originalElf.getSection(shstrtabIndex);
        Section savedShstrtab = savedElf.getSection(shstrtabIndex);

        long origShstrtabEnd = origShstrtab.getOffset() + origShstrtab.getSize();
        // Track expected offset: start from saved .shstrtab end
        long expectedOffset = savedShstrtab.getOffset() + savedShstrtab.getSize();

        int segmentCount = originalElf.getSegmentsCount();
        int savedSegmentCount = savedElf.getSegmentsCount();
        if (segmentCount != savedSegmentCount) {
            LOGGER.warn("Segment count mismatch: original={}, saved={}", segmentCount, savedSegmentCount);
            return false;
        }

        for (int i = 0; i < segmentCount; i++) {
            Segment origSeg = originalElf.getSegment(i);
            Segment savedSeg = savedElf.getSegment(i);

            if (origSeg == null || savedSeg == null) {
                LOGGER.warn("Segment {} is null", i);
                return false;
            }

            // Only validate segments whose original file offset is after .shstrtab
            long origOffset = origSeg.getOffset();
            if (origOffset < origShstrtabEnd) {
                continue;
            }

            // File size and memory size must remain unchanged
            if (origSeg.getFileSize() != savedSeg.getFileSize()) {
                LOGGER.warn("Segment " + i + " file size changed after .shstrtab: original=" + origSeg.getFileSize()
                    + ", saved=" + savedSeg.getFileSize());
            }
            if (origSeg.getMemorySize() != savedSeg.getMemorySize()) {
                LOGGER.warn("Segment " + i + " memory size changed after .shstrtab: original="
                    + origSeg.getMemorySize() + ", saved=" + savedSeg.getMemorySize());
            }

            // Calculate expected offset considering alignment
            long align = origSeg.getAlign();
            if (align > 1) {
                expectedOffset = (expectedOffset + align - 1) / align * align;
            }

            // Offset must match expected value
            if (savedSeg.getOffset() != expectedOffset) {
                LOGGER.warn("Segment {} offset mismatch: expected=" + expectedOffset + ", actual="
                        + savedSeg.getOffset() + ", align=" + align, i);
            }

            // Other properties must remain unchanged
            if (origSeg.getType() != savedSeg.getType() || origSeg.getFlags() != savedSeg.getFlags()
                || origSeg.getVirtualAddress() != savedSeg.getVirtualAddress()
                || origSeg.getPhysicalAddress() != savedSeg.getPhysicalAddress()
                || origSeg.getAlign() != savedSeg.getAlign()) {
                LOGGER.warn("Segment {} properties changed after .shstrtab", i);
                LOGGER.warn("Original " + buildSegmentInfo(origSeg));
                LOGGER.warn("Saved " + buildSegmentInfo(savedSeg));
            }

            // Advance expected offset by this segment's file size
            expectedOffset += savedSeg.getFileSize();
        }

        return true;
    }

    /**
     * Validate sections after .shstrtab (before signing sections) have correct offset shift.
     * For sections between .shstrtab and the first signing section (.profile/.permission/.codesign):
     * - Size must remain unchanged
     * - Offset must increase considering .shstrtab size increment and section alignment
     *
     * @param shstrtabIndex Index of .shstrtab section
     * @return true if validation passed
     */
    private boolean validateAfterShstrtabSections(int shstrtabIndex) {
        Section origShstrtab = originalElf.getSection(shstrtabIndex);
        Section savedShstrtab = savedElf.getSection(shstrtabIndex);

        long origShstrtabEnd = origShstrtab.getOffset() + origShstrtab.getSize();
        // Track expected offset: start from saved .shstrtab end
        long expectedOffset = savedShstrtab.getOffset() + savedShstrtab.getSize();

        int savedSectionsCount = savedElf.getSectionsCount();
        for (int i = shstrtabIndex + 1; i < savedSectionsCount; i++) {
            Section savedSec = savedElf.getSection(i);
            if (savedSec == null) {
                LOGGER.warn("Saved section {} is null", i);
                return false;
            }

            // Skip signing sections (.profile, .permission, .codesign)
            String secName = savedSec.getName();
            if (CODE_SIGN_SEC_NAME.equals(secName) || PERMISSION_SEC_NAME.equals(secName) || PROFILE_SEC_NAME.equals(
                secName)) {
                break;
            }

            Section origSec = originalElf.getSection(i);
            if (origSec == null) {
                LOGGER.warn("Original section {} is null", i);
                return false;
            }

            // Only validate sections whose original offset is after .shstrtab
            if (origSec.getOffset() < origShstrtabEnd) {
                continue;
            }

            // Size must remain unchanged
            if (origSec.getSize() != savedSec.getSize()) {
                LOGGER.warn("Section " + secName + " size changed after .shstrtab: original={}, saved={}",
                    origSec.getSize(), savedSec.getSize());
                return false;
            }

            // Calculate expected offset considering alignment
            long addrAlign = origSec.getAddrAlign();
            if (addrAlign > 1) {
                expectedOffset = (expectedOffset + addrAlign - 1) / addrAlign * addrAlign;
            }

            // Offset must match expected value
            if (savedSec.getOffset() != expectedOffset) {
                LOGGER.warn("Section {} offset mismatch: expected=" + expectedOffset + ", actual="
                        + savedSec.getOffset() + ", align=" + addrAlign, secName);
            }

            // Other fields (type, flags, address, link, info, addrAlign, entSize) must remain unchanged
            if (origSec.getType() != savedSec.getType() || origSec.getFlags() != savedSec.getFlags()
                || origSec.getAddress() != savedSec.getAddress() || origSec.getLink() != savedSec.getLink()
                || origSec.getInfo() != savedSec.getInfo() || origSec.getAddrAlign() != savedSec.getAddrAlign()
                || origSec.getEntSize() != savedSec.getEntSize()) {
                LOGGER.warn("Section {} properties changed after .shstrtab", secName);
                LOGGER.warn("Original " + buildSectionInfo(origSec));
                LOGGER.warn("Saved " + buildSectionInfo(savedSec));
            }

            // Advance expected offset by this section's data size
            expectedOffset += savedSec.getSize();
        }

        return true;
    }

    /**
     * Build a string with all field information of a section.
     *
     * @param section ELF section
     * @return formatted string containing all section fields
     */
    public static String buildSectionInfo(Section section) {
        if (section == null) {
            return "Section is null";
        }
        return String.format("Section[name=%s, type=0x%x, flags=0x%x, address=0x%x, offset=0x%x, size=0x%x,"
                + " link=0x%x, info=0x%x, addrAlign=0x%x, entSize=0x%x]",
            section.getName(), section.getType(), section.getFlags(), section.getAddress(), section.getOffset(),
            section.getSize(), section.getLink(), section.getInfo(), section.getAddrAlign(), section.getEntSize());
    }

    /**
     * Build a string with all field information of a segment.
     *
     * @param segment ELF segment
     * @return formatted string containing all segment fields
     */
    public static String buildSegmentInfo(Segment segment) {
        if (segment == null) {
            return "Segment is null";
        }
        return String.format(
            "Segment[type=0x%x, flags=0x%x, vaddr=0x%x, paddr=0x%x, offset=0x%x, filesz=0x%x, memsz=0x%x, align=0x%x]",
            segment.getType(), segment.getFlags(), segment.getVirtualAddress(), segment.getPhysicalAddress(),
            segment.getOffset(), segment.getFileSize(), segment.getMemorySize(), segment.getAlign());
    }
}
