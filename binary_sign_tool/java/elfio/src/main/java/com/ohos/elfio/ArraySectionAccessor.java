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

/**
 * Accessor for array-type sections (e.g., INIT_ARRAY, FINI_ARRAY, PREINIT_ARRAY).
 * These sections contain arrays of addresses (pointers to functions).
 *
 * @since 2026/3/5
 */
public class ArraySectionAccessor {
    private Section section;

    private boolean is64Bit;

    private ElfioUtils.EndiannessConvertor convertor;

    /**
     * Create an array section accessor.
     *
     * @param elfio The Elfio instance
     * @param section The array section
     */
    public ArraySectionAccessor(Elfio elfio, Section section) {
        this.section = section;
        this.convertor = elfio.getConvertor();
        // Determine if 64-bit based on address size (ELF class)
        this.is64Bit = (elfio.getElfClass() == ElfTypes.ELFCLASS64);
    }

    /**
     * Get the number of entries in the array.
     *
     * @return Number of entries
     */
    public int getEntriesNum() {
        int entrySize = is64Bit ? 8 : 4;
        return (int) (section.getSize() / entrySize);
    }

    /**
     * Get an entry at the specified index.
     *
     * @param index The entry index
     * @return The address value, or -1 if index is invalid
     */
    public long getEntry(int index) {
        int entrySize = is64Bit ? 8 : 4;
        if (index >= getEntriesNum()) {
            return -1;
        }

        byte[] data = section.getData();
        int offset = index * entrySize;

        if (offset + entrySize > data.length) {
            return -1;
        }

        ByteBuffer buffer = ByteBuffer.wrap(data, offset, entrySize);
        buffer.order(convertor.getByteOrder());

        if (is64Bit) {
            return buffer.getLong();
        } else {
            return buffer.getInt() & 0xFFFFFFFFL;
        }
    }

    /**
     * Add an entry to the array.
     *
     * @param address The address to add
     */
    public void addEntry(long address) {
        int entrySize = is64Bit ? 8 : 4;
        byte[] currentData = section.getData();
        byte[] newData = new byte[currentData.length + entrySize];

        System.arraycopy(currentData, 0, newData, 0, currentData.length);

        ByteBuffer buffer = ByteBuffer.wrap(newData, currentData.length, entrySize);
        buffer.order(convertor.getByteOrder());

        if (is64Bit) {
            buffer.putLong(address);
        } else {
            buffer.putInt((int) address);
        }

        section.setData(newData);
    }

    /**
     * Set an entry at the specified index.
     *
     * @param index The entry index
     * @param address The address value
     * @return true if successful
     */
    public boolean setEntry(int index, long address) {
        int entrySize = is64Bit ? 8 : 4;
        if (index >= getEntriesNum()) {
            return false;
        }

        byte[] data = section.getData();
        int offset = index * entrySize;

        if (offset + entrySize > data.length) {
            return false;
        }

        ByteBuffer buffer = ByteBuffer.wrap(data, offset, entrySize);
        buffer.order(convertor.getByteOrder());

        if (is64Bit) {
            buffer.putLong(address);
        } else {
            buffer.putInt((int) address);
        }

        return true;
    }
}
