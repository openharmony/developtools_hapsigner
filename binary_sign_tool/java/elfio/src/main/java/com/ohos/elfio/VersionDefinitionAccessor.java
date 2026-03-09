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
 * Accessor for GNU version definition section (SHT_GNU_verdef).
 * Contains information about defined versions.
 *
 * @since 2026/3/5
 */
public class VersionDefinitionAccessor {
    private Section section;

    private ElfioUtils.EndiannessConvertor convertor;

    private byte[] data;

    private Elfio elfio;

    /**
     * Create a version definition accessor.
     *
     * @param elfio The Elfio instance
     * @param section The version definition section
     */
    public VersionDefinitionAccessor(Elfio elfio, Section section) {
        this.elfio = elfio;
        this.section = section;
        this.convertor = elfio.getConvertor();
        this.data = section.getData();
    }

    /**
     * Create a version definition accessor without Elfio reference.
     *
     * @param section The version definition section
     * @param convertor Endianness convertor
     */
    public VersionDefinitionAccessor(Section section, ElfioUtils.EndiannessConvertor convertor) {
        this(null, section);
        this.convertor = convertor;
    }

    /**
     * Get the number of version definitions.
     *
     * @return Number of version definitions
     */
    public int getVersionDefinitionsNum() {
        if (data == null || data.length < 20) {
            return 0;
        }

        ByteBuffer dataBuffer = ByteBuffer.wrap(data);
        dataBuffer.order(convertor.getByteOrder());

        // Skip: vd_version (2), vd_cnt (2), vd_aux (4/8), vd_next (4/8)
        // We need to traverse the linked list
        int count = 0;
        int currentOffset = 0;
        int entrySize = (elfio != null && elfio.getElfClass() == ElfTypes.ELFCLASS64) ? 28 : 20;

        while (currentOffset + entrySize <= data.length) {
            count++;

            // Get vd_next to find next entry
            dataBuffer.position(
                currentOffset + (elfio != null && elfio.getElfClass() == ElfTypes.ELFCLASS64 ? 24 : 16));
            int vdNext = (elfio != null && elfio.getElfClass() == ElfTypes.ELFCLASS64)
                ? (int) dataBuffer.getLong()
                : dataBuffer.getInt();

            if (vdNext == 0) {
                break;
            }
            currentOffset += vdNext;
        }

        return count;
    }

    /**
     * Get a version definition entry.
     *
     * @param index The entry index
     * @param strSection The string section for name lookup
     * @return VersionDefinitionEntry object, or null if index is invalid
     */
    public VersionDefinitionEntry getEntry(int index, Section strSection) {
        if (data == null || index < 0) {
            return null;
        }

        ByteBuffer dataBuffer = ByteBuffer.wrap(data);
        dataBuffer.order(convertor.getByteOrder());

        int currentOffset = 0;
        int entrySize = (elfio != null && elfio.getElfClass() == ElfTypes.ELFCLASS64) ? 28 : 20;
        int count = 0;
        boolean is64Bit = (elfio != null && elfio.getElfClass() == ElfTypes.ELFCLASS64);

        while (currentOffset + entrySize <= data.length) {
            dataBuffer.position(currentOffset);

            if (count == index) {
                return parseVersionDefinitionEntry(dataBuffer, currentOffset, is64Bit, strSection);
            }

            // Move to next entry
            dataBuffer.position(currentOffset + (is64Bit ? 24 : 16));
            int vdNext = dataBuffer.getInt();
            if (vdNext == 0) {
                break;
            }
            currentOffset += vdNext;
            count++;
        }

        return null;
    }

    private VersionDefinitionEntry parseVersionDefinitionEntry(ByteBuffer dataBuffer, int currentOffset,
        boolean is64Bit, Section strSection) {
        int version = dataBuffer.getShort() & 0xFFFF;      // vd_version
        int flags = dataBuffer.getShort() & 0xFFFF;        // vd_flags
        int versionIndex = dataBuffer.getShort() & 0xFFFF;        // vd_ndx
        int countValue = dataBuffer.getShort() & 0xFFFF;        // vd_cnt
        int vdAux = is64Bit ? (int) dataBuffer.getLong() : dataBuffer.getInt();    // vd_aux

        String name = null;
        List<String> dependencies = null;
        if (strSection != null && vdAux != 0) {
            dependencies = new ArrayList<>();
            StringSectionAccessor strAccessor = new StringSectionAccessor(strSection);
            name = readVersionName(dataBuffer, currentOffset, vdAux, is64Bit, strAccessor);
            collectVersionDependencies(dataBuffer, currentOffset, vdAux, countValue, is64Bit, strAccessor,
                dependencies);
        }
        return new VersionDefinitionEntry(version, flags, versionIndex, countValue, name, dependencies);
    }

    private String readVersionName(ByteBuffer dataBuffer, int currentOffset, int vdAux, boolean is64Bit,
        StringSectionAccessor strAccessor) {
        int auxAbsOffset = currentOffset + vdAux;
        dataBuffer.position(auxAbsOffset);
        int vdaName = is64Bit ? (int) dataBuffer.getLong() : dataBuffer.getInt();    // vda_name
        return strAccessor.getString(vdaName);
    }

    private void collectVersionDependencies(ByteBuffer dataBuffer, int currentOffset, int vdAux, int countValue,
        boolean is64Bit, StringSectionAccessor strAccessor, List<String> dependencies) {
        int auxOffset = vdAux;
        for (int i = 0; i < countValue; i++) {
            dataBuffer.position(currentOffset + auxOffset);
            int vdaNext = is64Bit ? (int) dataBuffer.getLong() : dataBuffer.getInt();
            int depNameOffset = is64Bit ? (int) dataBuffer.getLong() : dataBuffer.getInt();
            String depName = strAccessor.getString(depNameOffset);
            if (depName != null && !depName.isEmpty()) {
                dependencies.add(depName);
            }
            if (vdaNext == 0) {
                break;
            }
            auxOffset += vdaNext;
        }
    }

    /**
     * Version definition entry.
     */
    public static class VersionDefinitionEntry {
        public final int version;       // vd_version

        public final int flags;         // vd_flags

        public final int index;         // vd_ndx

        public final int count;         // vd_cnt

        public final String name;       // Version name

        public final List<String> dependencies; // Dependency names

        public VersionDefinitionEntry(int version, int flags, int index, int count, String name,
            List<String> dependencies) {
            this.version = version;
            this.flags = flags;
            this.index = index;
            this.count = count;
            this.name = name;
            this.dependencies = dependencies;
        }
    }
}
