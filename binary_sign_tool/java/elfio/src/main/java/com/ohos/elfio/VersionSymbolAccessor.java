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
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Accessor for GNU version symbols (SHT_GNU_versym).
 * This section contains version indices for each symbol in the symbol table.
 *
 * @since 2026/3/5
 */
public class VersionSymbolAccessor {
    private Section section;

    private ElfioUtils.EndiannessConvertor convertor;

    private byte[] data;

    /**
     * Create a version symbol accessor.
     *
     * @param section The version symbol section (SHT_GNU_versym)
     */
    public VersionSymbolAccessor(Section section) {
        this(section, null);
    }

    /**
     * Create a version symbol accessor with endianness convertor.
     *
     * @param section The version symbol section
     * @param convertor Endianness convertor
     */
    public VersionSymbolAccessor(Section section, ElfioUtils.EndiannessConvertor convertor) {
        this.section = section;
        this.convertor = convertor;
        this.data = section.getData();
    }

    /**
     * Get the number of version entries.
     *
     * @return Number of entries
     */
    public int getEntriesNum() {
        // Each entry is 2 bytes (Elf64_Half)
        return (int) (section.getSize() / 2);
    }

    /**
     * Get version index for a symbol.
     *
     * @param symbolIndex The symbol index
     * @return Version index (0 = local, 1 = global, 2+ = specific version)
     */
    public int getVersionIndex(int symbolIndex) {
        if (symbolIndex < 0 || symbolIndex >= getEntriesNum()) {
            return 0;
        }

        if (data == null || symbolIndex * 2 + 2 > data.length) {
            return 0;
        }

        ByteBuffer buffer = ByteBuffer.wrap(data, symbolIndex * 2, 2);
        if (convertor != null) {
            buffer.order(convertor.getByteOrder());
        } else {
            buffer.order(ByteOrder.LITTLE_ENDIAN);
        }

        return buffer.getShort() & 0xFFFF;
    }

    /**
     * Set version index for a symbol.
     *
     * @param symbolIndex The symbol index
     * @param versionIndex The version index
     * @return true if successful
     */
    public boolean setVersionIndex(int symbolIndex, int versionIndex) {
        if (symbolIndex < 0 || symbolIndex >= getEntriesNum()) {
            return false;
        }

        if (data == null || symbolIndex * 2 + 2 > data.length) {
            return false;
        }

        ByteBuffer buffer = ByteBuffer.wrap(data, symbolIndex * 2, 2);
        if (convertor != null) {
            buffer.order(convertor.getByteOrder());
        } else {
            buffer.order(ByteOrder.LITTLE_ENDIAN);
        }

        buffer.putShort((short) versionIndex);
        return true;
    }

    /**
     * Get all version indices.
     *
     * @return List of version indices
     */
    public List<Integer> getAllVersionIndices() {
        List<Integer> indices = new ArrayList<>();
        for (int i = 0; i < getEntriesNum(); i++) {
            indices.add(getVersionIndex(i));
        }
        return indices;
    }

    /**
     * Modify version index for a symbol.
     *
     * @param symbolIndex The symbol index
     * @param versionIndex The version index
     * @return true if successful
     */
    public boolean modifyEntry(int symbolIndex, int versionIndex) {
        return setVersionIndex(symbolIndex, versionIndex);
    }

    /**
     * Add a new version entry.
     *
     * @param versionIndex The version index
     * @return true if successful
     */
    public boolean addEntry(int versionIndex) {
        byte[] valueData = new byte[2];
        ByteBuffer buffer = ByteBuffer.wrap(valueData);
        if (convertor != null) {
            buffer.order(convertor.getByteOrder());
        } else {
            buffer.order(ByteOrder.LITTLE_ENDIAN);
        }
        buffer.putShort((short) versionIndex);

        section.appendData(valueData);
        return true;
    }
}
