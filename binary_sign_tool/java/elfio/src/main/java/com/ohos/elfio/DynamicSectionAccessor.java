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
 * Accessor for dynamic sections.
 *
 * @since 2026/3/5
 */
public class DynamicSectionAccessor {
    private Section section;

    private Elfio elfio;

    private boolean is64Bit;

    /**
     * Create a dynamic section accessor.
     *
     * @param elfio The Elfio instance
     * @param section The dynamic section
     */
    public DynamicSectionAccessor(Elfio elfio, Section section) {
        this.elfio = elfio;
        this.section = section;
        int entsize = (int) section.getEntSize();
        this.is64Bit = (entsize == 16);
    }

    /**
     * Create a dynamic section accessor (without Elfio reference).
     *
     * @param section The dynamic section
     */
    public DynamicSectionAccessor(Section section) {
        this(null, section);
    }

    /**
     * Get the number of dynamic entries.
     *
     * @return Number of entries
     */
    public int getEntriesNum() {
        int entrySize = is64Bit ? 16 : 8;
        return (int) (section.getSize() / entrySize);
    }

    /**
     * Get a dynamic entry.
     *
     * @param index The entry index
     * @return DynamicEntry object
     */
    public DynamicEntry getEntry(int index) {
        byte[] data = section.getData();
        int entrySize = is64Bit ? 16 : 8;
        int offset = index * entrySize;

        if (offset + entrySize > data.length) {
            return null;
        }

        ByteBuffer buffer = ByteBuffer.wrap(data, offset, entrySize);
        buffer.order((elfio != null) ? elfio.getConvertor().getByteOrder() : ByteOrder.LITTLE_ENDIAN);

        if (is64Bit) {
            return new DynamicEntry(buffer.getLong(), buffer.getLong());
        } else {
            return new DynamicEntry(buffer.getInt() & 0xFFFFFFFFL, buffer.getInt() & 0xFFFFFFFFL);
        }
    }

    /**
     * Get a dynamic entry with string value.
     *
     * @param index The entry index
     * @param strSection The string section (for resolving string values)
     * @return DynamicEntryWithString object
     */
    public DynamicEntryWithString getEntryString(int index, Section strSection) {
        DynamicEntry entry = getEntry(index);
        if (entry == null) {
            return null;
        }

        String str = null;
        // If the tag has a string table reference, get the string.
        if (isStringTag(entry.tag) && strSection != null) {
            StringSectionAccessor strAccessor = new StringSectionAccessor(strSection);
            str = strAccessor.getString((int) entry.val);
        }

        return new DynamicEntryWithString(entry, str);
    }

    private boolean isStringTag(long tag) {
        return tag == ElfTypes.DT_NEEDED || tag == ElfTypes.DT_SONAME || tag == ElfTypes.DT_RPATH
            || tag == ElfTypes.DT_RUNPATH;
    }

    /**
     * Get all dynamic entries.
     *
     * @return List of dynamic entries
     */
    public List<DynamicEntry> getAllEntries() {
        List<DynamicEntry> entries = new ArrayList<>();
        int num = getEntriesNum();
        for (int i = 0; i < num; i++) {
            DynamicEntry entry = getEntry(i);
            if (entry != null && entry.tag != ElfTypes.DT_NULL) {
                entries.add(entry);
            } else {
                break; // DT_NULL marks the end
            }
        }
        return entries;
    }

    /**
     * Add a dynamic entry.
     *
     * @param tag The entry tag
     * @param val The entry value
     */
    public void addEntry(long tag, long val) {
        byte[] currentData = section.getData();
        int entrySize = is64Bit ? 16 : 8;
        byte[] newData = new byte[currentData.length + entrySize];

        System.arraycopy(currentData, 0, newData, 0, currentData.length);

        ByteBuffer buffer = ByteBuffer.wrap(newData, currentData.length, entrySize);
        buffer.order((elfio != null) ? elfio.getConvertor().getByteOrder() : ByteOrder.LITTLE_ENDIAN);

        if (is64Bit) {
            buffer.putLong(tag);
            buffer.putLong(val);
        } else {
            buffer.putInt((int) tag);
            buffer.putInt((int) val);
        }

        section.setData(newData);
    }

    /**
     * Add a dynamic entry with string value.
     *
     * @param tag The entry tag
     * @param str The string value
     * @param strSection The string section to add the string to
     */
    public void addEntry(long tag, String str, Section strSection) {
        if (strSection == null) {
            return;
        }
        StringSectionAccessor strAccessor = new StringSectionAccessor(strSection);
        int strOffset = strAccessor.addString(str);
        addEntry(tag, strOffset);
    }

    /**
     * Dynamic entry class.
     */
    public static class DynamicEntry {
        public final long tag;

        public final long val;

        public DynamicEntry(long tag, long val) {
            this.tag = tag;
            this.val = val;
        }
    }

    /**
     * Dynamic entry with string value.
     */
    public static class DynamicEntryWithString extends DynamicEntry {
        public final String str;

        public DynamicEntryWithString(DynamicEntry entry, String str) {
            super(entry.tag, entry.val);
            this.str = str;
        }
    }
}
