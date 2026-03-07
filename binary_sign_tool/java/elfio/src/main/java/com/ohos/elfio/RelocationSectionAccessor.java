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

/**
 * Accessor for relocation sections.
 *
 * @since 2026/3/5
 */
public class RelocationSectionAccessor {
    private Section section;

    private Elfio elfio;

    private boolean is64Bit;

    private boolean hasAddend;

    /**
     * Create a relocation section accessor.
     *
     * @param elfio The Elfio instance (for byte order and section lookup)
     * @param section The relocation section
     */
    public RelocationSectionAccessor(Elfio elfio, Section section) {
        this.elfio = elfio;
        this.section = section;
        // Determine if RELA (has addend) or REL (no addend)
        int type = section.getType();
        this.hasAddend = (type == ElfTypes.SHT_RELA);
        // Determine 32-bit vs 64-bit from ELF class (not from entsize)
        if (elfio != null) {
            this.is64Bit = (elfio.getElfClass() == ElfTypes.ELFCLASS64);
        } else {
            // Fallback: guess from entsize if elfio is null
            int entsize = (int) section.getEntSize();
            this.is64Bit = (entsize == 24) || (entsize == 16);
        }
    }

    /**
     * Create a relocation section accessor without Elfio reference.
     *
     * @param section The relocation section
     * @deprecated Use RelocationSectionAccessor(Elfio, Section) for proper byte order support
     */
    @Deprecated
    public RelocationSectionAccessor(Section section) {
        this(null, section);
    }

    /**
     * Get the number of relocation entries.
     *
     * @return Number of entries
     */
    public int getEntriesNum() {
        int entrySize = getEntrySize();
        if (entrySize == 0) {
            return 0;
        }
        return (int) (section.getSize() / entrySize);
    }

    private int getEntrySize() {
        if (is64Bit) {
            return hasAddend ? 24 : 16;
        } else {
            return hasAddend ? 12 : 8;
        }
    }

    /**
     * Get a relocation entry.
     *
     * @param index The entry index
     * @param symStrSection The symbol string section
     * @return RelocationEntry object
     */
    public RelocationEntry getEntry(int index, Section symStrSection) {
        byte[] data = section.getData();
        int entrySize = getEntrySize();
        int offset = index * entrySize;

        if (offset + entrySize > data.length) {
            return null;
        }

        ByteOrder byteOrder = (elfio != null) ? elfio.getConvertor().getByteOrder() : ByteOrder.LITTLE_ENDIAN;
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, entrySize);
        buffer.order(byteOrder);

        long relOffset;
        int symbolIndex;
        int relType;
        long relAddend = 0L;

        if (is64Bit) {
            relOffset = buffer.getLong();
            long info = buffer.getLong();
            symbolIndex = (int) (info >>> 32);
            relType = (int) (info & 0xFFFFFFFFL);
            if (hasAddend) {
                relAddend = buffer.getLong();
            }
        } else {
            relOffset = buffer.getInt() & 0xFFFFFFFFL;
            int info = buffer.getInt();
            symbolIndex = info >>> 8;
            relType = info & 0xFF;
            if (hasAddend) {
                relAddend = buffer.getInt();
            }
        }

        String symbolName = null;
        long symbolValue = 0L;
        // Get symbol name from symbol table (link section)
        if (elfio != null && symbolIndex != 0) {
            int linkIndex = (int) section.getLink();
            Section symtab = elfio.getSection(linkIndex);
            if (symtab != null) {
                SymbolSectionAccessor symAccessor = new SymbolSectionAccessor(elfio, symtab);
                SymbolSectionAccessor.Symbol sym = symAccessor.getSymbol(symbolIndex, symStrSection);
                if (sym != null) {
                    symbolName = sym.nameStr;
                    symbolValue = sym.value;
                }
            }
        }

        return new RelocationEntry(relOffset, symbolIndex, relType, relAddend, symbolName, symbolValue);
    }

    /**
     * Get a relocation entry with calculated value.
     *
     * @param index The entry index
     * @param symStrSection The symbol string section
     * @return RelocationEntryWithCalc object
     */
    public RelocationEntryWithCalc getEntryWithCalc(int index, Section symStrSection) {
        RelocationEntry entry = getEntry(index, symStrSection);
        if (entry == null) {
            return null;
        }
        long calcValue = calculateRelocationValue(entry.type, entry.symbolValue, entry.addend, entry.offset);
        return new RelocationEntryWithCalc(entry, calcValue);
    }

    /**
     * Calculate relocation value based on type.
     */
    private long calculateRelocationValue(int type, long symbolValue, long addend, long offset) {
        if (type == 0 || type == 3 || type == 4) {
            return 0;
        }
        if (isSymbolOnlyRelocation(type)) {
            return symbolValue;
        }
        if (isAddendOnlyRelocation(type)) {
            return addend;
        }
        if (isPcRelativeRelocation(type)) {
            return symbolValue + addend - offset;
        }
        if (isAbsoluteRelocation(type)) {
            return symbolValue + addend;
        }
        return 0;
    }

    private boolean isSymbolOnlyRelocation(int type) {
        return type == 5 || type == 6 || type == 7;
    }

    private boolean isAddendOnlyRelocation(int type) {
        return type == 8 || type == 37 || type == 42;
    }

    private boolean isPcRelativeRelocation(int type) {
        return type == 2 || type == 13 || type == 15 || type == 21 || type == 23;
    }

    private boolean isAbsoluteRelocation(int type) {
        return type == 1 || type == 9 || type == 10 || type == 11 || type == 12 || type == 14 || type == 20
            || type == 22;
    }

    /**
     * Set a relocation entry.
     *
     * @param index The entry index
     * @param offset Relocation offset
     * @param symbol Symbol index
     * @param type Relocation type
     * @param addend Addend (ignored for REL sections)
     * @return true if successful
     */
    public boolean setEntry(int index, long offset, int symbol, int type, long addend) {
        byte[] data = section.getData();
        int entrySize = getEntrySize();
        int entryOffset = index * entrySize;

        if (entryOffset + entrySize > data.length) {
            return false;
        }

        ByteOrder byteOrder = (elfio != null) ? elfio.getConvertor().getByteOrder() : ByteOrder.LITTLE_ENDIAN;
        ByteBuffer buffer = ByteBuffer.wrap(data, entryOffset, entrySize);
        buffer.order(byteOrder);

        if (is64Bit) {
            buffer.putLong(offset);
            long info = ElfTypes.ELF64_R_INFO(symbol, type);
            buffer.putLong(info);
            if (hasAddend) {
                buffer.putLong(addend);
            }
        } else {
            buffer.putInt((int) offset);
            int info = ElfTypes.ELF32_R_INFO(symbol, type);
            buffer.putInt(info);
            if (hasAddend) {
                buffer.putInt((int) addend);
            }
        }

        return true;
    }

    /**
     * Add a relocation entry (without addend).
     * For REL sections, this creates an entry without addend.
     * For RELA sections, this creates an entry with addend=0.
     *
     * @param offset Relocation offset
     * @param info Relocation info (symbol + type)
     */
    public void addEntry(long offset, long info) {
        byte[] currentData = section.getData();
        int entrySize = getEntrySize();
        byte[] newData = new byte[currentData.length + entrySize];
        System.arraycopy(currentData, 0, newData, 0, currentData.length);

        ByteOrder byteOrder = (elfio != null) ? elfio.getConvertor().getByteOrder() : ByteOrder.LITTLE_ENDIAN;
        ByteBuffer buffer = ByteBuffer.wrap(newData, currentData.length, entrySize);
        buffer.order(byteOrder);

        if (is64Bit) {
            buffer.putLong(offset);
            buffer.putLong(info);
            if (hasAddend) {
                buffer.putLong(0); // addend = 0 for RELA
            }
        } else {
            buffer.putInt((int) offset);
            buffer.putInt((int) info);
            if (hasAddend) {
                buffer.putInt(0); // addend = 0 for RELA
            }
        }

        section.setData(newData);
    }

    /**
     * Add a relocation entry.
     *
     * @param offset Relocation offset
     * @param symbol Symbol index
     * @param type Relocation type
     */
    public void addEntry(long offset, int symbol, int type) {
        long info;
        if (is64Bit) {
            info = ElfTypes.ELF64_R_INFO(symbol, type);
        } else {
            info = ElfTypes.ELF32_R_INFO(symbol, type);
        }
        addEntry(offset, info);
    }

    /**
     * Add a relocation entry with addend (for RELA sections).
     *
     * @param offset Relocation offset
     * @param info Relocation info (symbol + type)
     * @param addend Addend value
     */
    public void addEntry(long offset, long info, long addend) {
        byte[] currentData = section.getData();
        int entrySize = getEntrySize();
        byte[] newData = new byte[currentData.length + entrySize];
        System.arraycopy(currentData, 0, newData, 0, currentData.length);

        ByteOrder byteOrder = (elfio != null) ? elfio.getConvertor().getByteOrder() : ByteOrder.LITTLE_ENDIAN;
        ByteBuffer buffer = ByteBuffer.wrap(newData, currentData.length, entrySize);
        buffer.order(byteOrder);

        if (is64Bit) {
            buffer.putLong(offset);
            buffer.putLong(info);
            buffer.putLong(addend);
        } else {
            buffer.putInt((int) offset);
            buffer.putInt((int) info);
            buffer.putInt((int) addend);
        }

        section.setData(newData);
    }

    /**
     * Add a relocation entry with addend.
     *
     * @param offset Relocation offset
     * @param symbol Symbol index
     * @param type Relocation type
     * @param addend Addend value
     */
    public void addEntry(long offset, int symbol, int type, long addend) {
        long info;
        if (is64Bit) {
            info = ElfTypes.ELF64_R_INFO(symbol, type);
        } else {
            info = ElfTypes.ELF32_R_INFO(symbol, type);
        }
        addEntry(offset, info, addend);
    }

    /**
     * Add a complete relocation entry with symbol.
     *
     * @param strWriter String section accessor
     * @param symWriter Symbol section accessor
     * @param name Symbol name
     * @param value Symbol value
     * @param size Symbol size
     * @param bind Symbol binding
     * @param type Symbol type
     * @param other Symbol other
     * @param shndx Section index
     * @param offset Relocation offset
     * @param relType Relocation type
     */
    public void addEntry(StringSectionAccessor strWriter, SymbolSectionAccessor symWriter, String name, long value,
        long size, byte bind, byte type, byte other, short shndx, long offset, int relType) {
        int symIndex = symWriter.addSymbol(strWriter, name, value, size, ElfTypes.ELF_ST_INFO(bind, type), other,
            shndx);
        addEntry(offset, symIndex, relType);
    }

    /**
     * Swap symbol references in all relocation entries.
     *
     * @param first First symbol index
     * @param second Second symbol index
     */
    public void swapSymbols(int first, int second) {
        for (int i = 0; i < getEntriesNum(); i++) {
            byte[] data = section.getData();
            int entrySize = getEntrySize();
            int offset = i * entrySize;

            if (offset + entrySize > data.length) {
                continue;
            }

            ByteOrder byteOrder = (elfio != null) ? elfio.getConvertor().getByteOrder() : ByteOrder.LITTLE_ENDIAN;
            ByteBuffer buffer = ByteBuffer.wrap(data, offset, entrySize);
            buffer.order(byteOrder);

            int symbolIndex;
            long relOffset;
            int relType;
            long addend = 0L;

            if (is64Bit) {
                relOffset = buffer.getLong();
                long info = buffer.getLong();
                symbolIndex = (int) (info >>> 32);
                relType = (int) (info & 0xFFFFFFFFL);
                if (hasAddend) {
                    addend = buffer.getLong();
                }
            } else {
                relOffset = buffer.getInt() & 0xFFFFFFFFL;
                int info = buffer.getInt();
                symbolIndex = info >>> 8;
                relType = info & 0xFF;
                if (hasAddend) {
                    addend = buffer.getInt();
                }
            }

            if (symbolIndex == first) {
                setEntry(i, relOffset, second, relType, addend);
            } else if (symbolIndex == second) {
                setEntry(i, relOffset, first, relType, addend);
            }
        }
    }

    /**
     * Relocation entry class.
     */
    public static class RelocationEntry {
        public final long offset;

        public final int symbolIndex;

        public final int type;

        public final long addend;

        public final String symbolName;

        public final long symbolValue;

        public RelocationEntry(long offset, int symbolIndex, int type, long addend, String symbolName,
            long symbolValue) {
            this.offset = offset;
            this.symbolIndex = symbolIndex;
            this.type = type;
            this.addend = addend;
            this.symbolName = symbolName;
            this.symbolValue = symbolValue;
        }

        // For RELA entries with addend
        public boolean hasAddend() {
            return addend != 0 || type != 0;
        }
    }

    /**
     * Relocation entry with calculated value.
     */
    public static class RelocationEntryWithCalc extends RelocationEntry {
        public final long calcValue;

        public RelocationEntryWithCalc(RelocationEntry entry, long calcValue) {
            super(entry.offset, entry.symbolIndex, entry.type, entry.addend, entry.symbolName, entry.symbolValue);
            this.calcValue = calcValue;
        }
    }
}
