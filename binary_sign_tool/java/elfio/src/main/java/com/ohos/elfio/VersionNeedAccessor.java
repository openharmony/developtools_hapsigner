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

package com.ohos.elfio;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Accessor for GNU version need section (SHT_GNU_verneed).
 * Contains information about required versions.
 *
 * @since 2026/3/5
 */
public class VersionNeedAccessor {
    private Section section;

    private ElfioUtils.EndiannessConvertor convertor;

    private byte[] data;

    private Elfio elfio;

    private int entriesNum = 0;

    /**
     * Create a version need accessor.
     *
     * @param elfio The Elfio instance
     * @param section The version need section
     */
    public VersionNeedAccessor(Elfio elfio, Section section) {
        this.elfio = elfio;
        this.section = section;
        this.convertor = elfio.getConvertor();
        this.data = section.getData();

        // Find DT_VERNEEDNUM in .dynamic section
        findEntriesNum();
    }

    /**
     * Create a version need accessor without Elfio reference.
     *
     * @param section The version need section
     * @param convertor Endianness convertor
     */
    public VersionNeedAccessor(Section section, ElfioUtils.EndiannessConvertor convertor) {
        this.elfio = null;
        this.section = section;
        this.convertor = convertor;
        this.data = section.getData();
    }

    private void findEntriesNum() {
        if (elfio == null) {
            return;
        }

        // Find .dynamic section
        Section dynamicSection = elfio.getSection(".dynamic");
        if (dynamicSection == null) {
            return;
        }

        DynamicSectionAccessor dynamicAcc = new DynamicSectionAccessor(elfio, dynamicSection);
        for (int i = 0; i < dynamicAcc.getEntriesNum(); i++) {
            DynamicSectionAccessor.DynamicEntry entry = dynamicAcc.getEntry(i);
            if (entry != null && entry.tag == ElfTypes.DT_VERNEEDNUM) {
                entriesNum = (int) entry.val;
                break;
            }
        }
    }

    /**
     * Get the number of version needs.
     *
     * @return Number of version needs
     */
    public int getVersionNeedsNum() {
        return entriesNum;
    }

    /**
     * Get a version need entry.
     *
     * @param index The entry index
     * @param strSection The string section for name lookup
     * @return VersionNeedEntry object, or null if index is invalid
     */
    public VersionNeedEntry getEntry(int index, Section strSection) {
        if (data == null || strSection == null || index < 0 || index >= entriesNum) {
            return null;
        }

        int currentOffset = 0;
        int entrySize = (elfio != null && elfio.getElfClass() == ElfTypes.ELFCLASS64) ? 32 : 24;
        int count = 0;
        boolean is64Bit = (elfio != null && elfio.getElfClass() == ElfTypes.ELFCLASS64);

        ByteBuffer dataBuffer = ByteBuffer.wrap(data);
        dataBuffer.order(convertor.getByteOrder());

        while (currentOffset + entrySize <= data.length) {
            dataBuffer.position(currentOffset);

            if (count == index) {
                int version = dataBuffer.getShort() & 0xFFFF;      // vn_version
                dataBuffer.getShort(); // skip padding
                int vnCnt = dataBuffer.getShort() & 0xFFFF;        // vn_cnt
                int vnFile = is64Bit ? (int) dataBuffer.getLong() : dataBuffer.getInt(); // vn_file
                int vnAux = is64Bit ? (int) dataBuffer.getLong() : dataBuffer.getInt();  // vn_aux
                // vn_next would follow

                // Get file name
                StringSectionAccessor strAccessor = new StringSectionAccessor(strSection);
                String fileName = strAccessor.getString(vnFile);

                // Get auxiliary entries
                List<VersionNeedAux> auxEntries = new ArrayList<>();
                int auxOffset = currentOffset + vnAux;
                for (int i = 0; i < vnCnt; i++) {
                    dataBuffer.position(auxOffset);

                    int hash = dataBuffer.getInt();                // vna_hash
                    int flags = dataBuffer.getShort() & 0xFFFF;      // vna_flags
                    int vnaOther = dataBuffer.getShort() & 0xFFFF;   // vna_other
                    int vnaName = is64Bit ? (int) dataBuffer.getLong() : dataBuffer.getInt(); // vna_name
                    String name = strAccessor.getString(vnaName);

                    auxEntries.add(new VersionNeedAux(vnaName, hash, flags, vnaOther, name));

                    // Move to next auxiliary entry
                    int vnaNext = is64Bit ? (int) dataBuffer.getLong() : dataBuffer.getInt();
                    if (vnaNext == 0) {
                        break;
                    }
                    auxOffset += vnaNext;
                }

                return new VersionNeedEntry(version, vnCnt, fileName, auxEntries);
            }

            // Move to next entry
            dataBuffer.position(currentOffset + (is64Bit ? 24 : 16));
            int vnNext = dataBuffer.getInt();
            if (vnNext == 0) {
                break;
            }
            currentOffset += vnNext;
            count++;
        }

        return null;
    }

    /**
     * Version need entry.
     */
    public static class VersionNeedEntry {
        public final int version;       // vn_version

        public final int count;         // vn_cnt

        public final String fileName;   // Dependency file name

        public final List<VersionNeedAux> auxEntries;

        public VersionNeedEntry(int version, int count, String fileName, List<VersionNeedAux> auxEntries) {
            this.version = version;
            this.count = count;
            this.fileName = fileName;
            this.auxEntries = auxEntries;
        }
    }

    /**
     * Auxiliary entry for version need.
     */
    public static class VersionNeedAux {
        public final int nameOffset;

        public final int hash;

        public final int flags;

        public final int other;         // vna_other

        public final String name;       // Version name

        public VersionNeedAux(int nameOffset, int hash, int flags, int other, String name) {
            this.nameOffset = nameOffset;
            this.hash = hash;
            this.flags = flags;
            this.other = other;
            this.name = name;
        }
    }
}
