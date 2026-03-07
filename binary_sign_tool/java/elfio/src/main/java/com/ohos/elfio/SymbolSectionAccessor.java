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

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Accessor for symbol table sections.
 *
 * @since 2026/3/5
 */
public class SymbolSectionAccessor {
    private Section section;

    private Elfio elfio;

    private ElfioUtils.EndiannessConvertor convertor;

    private byte fileClass;

    private boolean is64Bit;

    private Section hashSection;

    private int hashSectionIndex;

    /**
     * Create a symbol section accessor.
     *
     * @param section The symbol section
     */
    public SymbolSectionAccessor(Section section) {
        this(null, section);
    }

    /**
     * Create a symbol section accessor with Elfio reference.
     *
     * @param elfio The Elfio instance (for hash lookup support)
     * @param section The symbol section
     */
    public SymbolSectionAccessor(Elfio elfio, Section section) {
        this.elfio = elfio;
        this.section = section;
        // We need to infer file class from section size or other clues
        // For now, assume 64-bit if entsize is 24, else 32-bit
        this.is64Bit = (section.getEntSize() == 24);
        this.fileClass = is64Bit ? ElfTypes.ELFCLASS64 : ElfTypes.ELFCLASS32;
        this.hashSectionIndex = -1;

        if (elfio != null) {
            this.convertor = elfio.getConvertor();
            findHashSection();
        }
    }

    /**
     * Get the number of symbols.
     *
     * @return Number of symbols
     */
    public int getSymbolsNum() {
        int entrySize = is64Bit ? 24 : 16;
        return (int) (section.getSize() / entrySize);
    }

    /**
     * Get a symbol at the specified index.
     *
     * @param index The symbol index
     * @param linkSection The linked string section
     * @return Symbol object
     */
    public Symbol getSymbol(int index, Section linkSection) {
        byte[] data = section.getData();
        int entrySize = is64Bit ? 24 : 16;
        int offset = index * entrySize;

        if (offset + entrySize > data.length) {
            return null;
        }

        ByteBuffer buffer = ByteBuffer.wrap(data, offset, entrySize);
        buffer.order(
            (convertor != null) ? convertor.getByteOrder() : ByteOrder.LITTLE_ENDIAN); // Default, should use convertor

        int nameValue;
        long symbolValue;
        long symbolSize;
        byte symbolInfo;
        byte symbolOther;
        short symbolSectionIndex;
        if (is64Bit) {
            nameValue = buffer.getInt();
            symbolInfo = buffer.get();
            symbolOther = buffer.get();
            symbolSectionIndex = buffer.getShort();
            symbolValue = buffer.getLong();
            symbolSize = buffer.getLong();
        } else {
            nameValue = buffer.getInt();
            symbolValue = buffer.getInt() & 0xFFFFFFFFL;
            symbolSize = buffer.getInt() & 0xFFFFFFFFL;
            symbolInfo = buffer.get();
            symbolOther = buffer.get();
            symbolSectionIndex = buffer.getShort();
        }

        // Get name from string table
        String nameStr = null;
        if (linkSection != null) {
            StringSectionAccessor strAccessor = new StringSectionAccessor(linkSection);
            nameStr = strAccessor.getString(nameValue);
        }

        return new Symbol(nameValue, nameStr, symbolValue, symbolSize, symbolInfo, symbolOther, symbolSectionIndex);
    }

    /**
     * Add a symbol to the symbol table.
     *
     * @param name The symbol name
     * @param value Symbol value
     * @param size Symbol size
     * @param info Symbol info (binding + type)
     * @param other Symbol visibility
     * @param sectionIndex Section index
     * @param nameOffset Offset in string table
     */
    public void addSymbol(String name, long value, long size, byte info, byte other, short sectionIndex,
        int nameOffset) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] currentData = section.getData();
        baos.write(currentData, 0, currentData.length);

        ByteBuffer buffer;
        if (is64Bit) {
            buffer = ByteBuffer.allocate(24);
            buffer.order((convertor != null) ? convertor.getByteOrder() : ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(nameOffset);
            buffer.put(info);
            buffer.put(other);
            buffer.putShort(sectionIndex);
            buffer.putLong(value);
            buffer.putLong(size);
        } else {
            buffer = ByteBuffer.allocate(16);
            buffer.order((convertor != null) ? convertor.getByteOrder() : ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(nameOffset);
            buffer.putInt((int) value);
            buffer.putInt((int) size);
            buffer.put(info);
            buffer.put(other);
            buffer.putShort(sectionIndex);
        }

        baos.write(buffer.array(), 0, buffer.array().length);
        section.setData(baos.toByteArray());
    }

    /**
     * Add a symbol with separate bind and type.
     *
     * @param nameOffset Offset in string table
     * @param value Symbol value
     * @param size Symbol size
     * @param bind Symbol binding
     * @param type Symbol type
     * @param other Symbol visibility
     * @param sectionIndex Section index
     */
    public void addSymbol(int nameOffset, long value, long size, byte bind, byte type, byte other, short sectionIndex) {
        addSymbol(null, value, size, ElfTypes.ELF_ST_INFO(bind, type), other, sectionIndex, nameOffset);
    }

    /**
     * Add a symbol with automatic string table update.
     *
     * @param strWriter String section accessor
     * @param name Symbol name
     * @param value Symbol value
     * @param size Symbol size
     * @param info Symbol info
     * @param other Symbol visibility
     * @param sectionIndex Section index
     * @return The new symbol index
     */
    public int addSymbol(StringSectionAccessor strWriter, String name, long value, long size, byte info, byte other,
        short sectionIndex) {
        int nameOffset = strWriter.addString(name);
        addSymbol(null, value, size, info, other, sectionIndex, nameOffset);
        return getSymbolsNum() - 1;
    }

    /**
     * Get a symbol by name (linear search).
     *
     * @param name Symbol name to find
     * @param linkSection The linked string section
     * @return Symbol object, or null if not found
     */
    public Symbol getSymbol(String name, Section linkSection) {
        for (int i = 0; i < getSymbolsNum(); i++) {
            Symbol sym = getSymbol(i, linkSection);
            if (sym != null && name.equals(sym.nameStr)) {
                return sym;
            }
        }
        return null;
    }

    /**
     * Get a symbol by value (address).
     *
     * @param value Address to search for
     * @param linkSection The linked string section
     * @return Symbol object, or null if not found
     */
    public Symbol getSymbol(long value, Section linkSection) {
        for (int i = 0; i < getSymbolsNum(); i++) {
            Symbol sym = getSymbol(i, linkSection);
            if (sym != null && sym.value == value) {
                return sym;
            }
        }
        return null;
    }

    /**
     * Arrange local symbols - moves local symbols to the beginning of the table.
     *
     * @return The number of local symbols
     */
    public int arrangeLocalSymbols() {
        int firstNotLocal = 1; // Skip first entry (always NOTYPE)
        int count = getSymbolsNum();
        byte[] data = section.getData();
        int entrySize = is64Bit ? 24 : 16;

        while (true) {
            // Find first non-local symbol
            while (firstNotLocal < count) {
                int offset = firstNotLocal * entrySize;
                if (offset + entrySize <= data.length) {
                    byte info = data[offset + (is64Bit ? 4 : 12)]; // st_info offset
                    if (ElfTypes.ELF_ST_BIND(info) != ElfTypes.STB_LOCAL) {
                        break;
                    }
                }
                firstNotLocal++;
            }

            // Find next local symbol after non-local ones
            int current = firstNotLocal + 1;
            while (current < count) {
                int offset = current * entrySize;
                if (offset + entrySize <= data.length) {
                    byte info = data[offset + (is64Bit ? 4 : 12)];
                    if (ElfTypes.ELF_ST_BIND(info) == ElfTypes.STB_LOCAL) {
                        break;
                    }
                }
                current++;
            }

            if (firstNotLocal < count && current < count) {
                // Swap symbols
                swapSymbols(firstNotLocal, current);
            } else {
                // Update section info field
                section.setInfo(firstNotLocal);
                break;
            }
        }

        return firstNotLocal;
    }

    /**
     * Find the associated hash section for fast symbol lookup.
     */
    private void findHashSection() {
        if (elfio == null) {
            return;
        }

        int numSections = elfio.getSectionsCount();
        for (int i = 0; i < numSections; i++) {
            Section sec = elfio.getSection(i);
            if (sec != null && sec.getLink() == section.getIndex() && (sec.getType() == ElfTypes.SHT_HASH
                || sec.getType() == ElfTypes.SHT_GNU_HASH || sec.getType() == ElfTypes.DT_GNU_HASH)) {
                hashSection = sec;
                hashSectionIndex = i;
                break;
            }
        }
    }

    /**
     * Get the index of the hash section.
     *
     * @return Index of the hash section, or -1 if not found
     */
    public int getHashTableIndex() {
        return hashSectionIndex;
    }

    /**
     * Get the hash section.
     *
     * @return The hash section, or null if not found
     */
    public Section getHashSection() {
        return hashSection;
    }

    /**
     * Check if hash table lookup is available.
     *
     * @return true if hash section is found
     */
    public boolean hasHashTable() {
        return hashSectionIndex >= 0 && hashSection != null;
    }

    /**
     * Get symbol by name using hash table lookup if available.
     *
     * @param name Symbol name to find
     * @param linkSection The linked string section
     * @return Symbol object, or null if not found
     */
    public Symbol getSymbolWithHash(String name, Section linkSection) {
        if (hashSectionIndex >= 0 && hashSection != null) {
            // Check hash section type and use appropriate lookup method
            if (hashSection.getType() == ElfTypes.SHT_HASH) {
                Symbol result = hashLookup(name, linkSection);
                if (result != null) {
                    return result;
                }
            } else if (hashSection.getType() == ElfTypes.SHT_GNU_HASH
                || hashSection.getType() == ElfTypes.DT_GNU_HASH) {
                Symbol result = gnuHashLookup(name, linkSection);
                if (result != null) {
                    return result;
                }
            }
        }
        // Fallback to linear search
        return getSymbol(name, linkSection);
    }

    /**
     * SYSV hash table lookup (SHT_HASH).
     *
     * @param name Symbol name to find
     * @param linkSection The linked string section
     * @return Symbol object, or null if not found
     */
    private Symbol hashLookup(String name, Section linkSection) {
        if (hashSection == null || hashSection.getType() != ElfTypes.SHT_HASH) {
            return null;
        }

        byte[] hashData = hashSection.getData();
        if (hashData == null || hashData.length < 8) {
            return null;
        }

        ByteBuffer buffer = ByteBuffer.wrap(hashData);
        buffer.order(convertor.getByteOrder());

        int nbucket = buffer.getInt();
        int nchain = buffer.getInt();

        int hash = ElfioUtils.elfHash(name);
        int bucketIndex = 2 + (hash % nbucket);

        if (bucketIndex * 4 + 4 > hashData.length) {
            return null;
        }

        buffer.position(bucketIndex * 4);
        int y = buffer.getInt();

        while (y != 0 && y < nchain) {
            Symbol sym = getSymbol(y, linkSection);
            if (sym != null && name.equals(sym.nameStr)) {
                return sym;
            }

            int chainIndex = 2 + nbucket + y;
            if (chainIndex * 4 + 4 > hashData.length) {
                break;
            }
            buffer.position(chainIndex * 4);
            y = buffer.getInt();
        }

        return null;
    }

    /**
     * GNU hash table lookup (SHT_GNU_HASH or DT_GNU_HASH).
     *
     * @param name Symbol name to find
     * @param linkSection The linked string section
     * @return Symbol object, or null if not found
     */
    private Symbol gnuHashLookup(String name, Section linkSection) {
        if (hashSection == null || (hashSection.getType() != ElfTypes.SHT_GNU_HASH
            && hashSection.getType() != ElfTypes.DT_GNU_HASH)) {
            return null;
        }

        byte[] hashData = hashSection.getData();
        if (hashData == null || hashData.length < 16) {
            return null;
        }

        ByteBuffer buffer = ByteBuffer.wrap(hashData);
        buffer.order(convertor.getByteOrder());

        GnuHashHeader header = readGnuHashHeader(buffer);
        int hash = ElfioUtils.elfGnuHash(name);
        if (!passesBloomFilter(hashData, buffer, header, hash)) {
            return null;
        }

        int chainIndex = getInitialChainIndex(hashData, buffer, header, hash);
        if (chainIndex < 0) {
            return null;
        }
        return traverseGnuHashChain(hashData, buffer, header, hash, chainIndex, name, linkSection);
    }

    private GnuHashHeader readGnuHashHeader(ByteBuffer buffer) {
        int nbuckets = buffer.getInt();
        int symoffset = buffer.getInt();
        int bloomSize = buffer.getInt();
        int bloomShift = buffer.getInt();
        return new GnuHashHeader(nbuckets, symoffset, bloomSize, bloomShift, is64Bit ? 8 : 4);
    }

    private boolean passesBloomFilter(byte[] hashData, ByteBuffer buffer, GnuHashHeader header, int hash) {
        int bloomIndex = (hash / (8 * header.wordSize)) % header.bloomSize;
        int bloomEntryOffset = 16 + bloomIndex * header.wordSize;
        if (bloomEntryOffset + header.wordSize > hashData.length) {
            return false;
        }
        long bloomBits = ((1L << (hash % (8 * header.wordSize)))
            | (1L << ((hash >> header.bloomShift) % (8 * header.wordSize))));
        long bloomValue;
        buffer.position(bloomEntryOffset);
        if (is64Bit) {
            bloomValue = buffer.getLong();
        } else {
            bloomValue = buffer.getInt() & 0xFFFFFFFFL;
        }
        return (bloomValue & bloomBits) == bloomBits;
    }

    private int getInitialChainIndex(byte[] hashData, ByteBuffer buffer, GnuHashHeader header, int hash) {
        int bucket = hash % header.nbuckets;
        int bucketsOffset = 16 + header.bloomSize * header.wordSize;
        int bucketEntryOffset = bucketsOffset + bucket * 4;
        if (bucketEntryOffset + 4 > hashData.length) {
            return -1;
        }
        buffer.position(bucketEntryOffset);
        return buffer.getInt() - header.symoffset;
    }

    private Symbol traverseGnuHashChain(byte[] hashData, ByteBuffer buffer, GnuHashHeader header, int hash,
                                        int chainIndex, String name, Section linkSection) {
        if (chainIndex < 0) {
            return null;
        }
        int chainsOffset = 16 + header.bloomSize * header.wordSize + header.nbuckets * 4;
        int currentIndex = chainIndex;
        while (true) {
            int chainEntryOffset = chainsOffset + currentIndex * 4;
            if (chainEntryOffset + 4 > hashData.length) {
                return null;
            }
            buffer.position(chainEntryOffset);
            int chainHash = buffer.getInt();
            int symbolIndex = currentIndex + header.symoffset;
            if (((chainHash >> 1) == (hash >> 1)) && symbolIndex < getSymbolsNum()) {
                Symbol sym = getSymbol(symbolIndex, linkSection);
                if (sym != null && name.equals(sym.nameStr)) {
                    return sym;
                }
            }
            if ((chainHash & 1) != 0) {
                return null;
            }
            currentIndex++;
        }
    }

    private static class GnuHashHeader {
        private final int nbuckets;
        private final int symoffset;
        private final int bloomSize;
        private final int bloomShift;
        private final int wordSize;

        GnuHashHeader(int nbuckets, int symoffset, int bloomSize, int bloomShift, int wordSize) {
            this.nbuckets = nbuckets;
            this.symoffset = symoffset;
            this.bloomSize = bloomSize;
            this.bloomShift = bloomShift;
            this.wordSize = wordSize;
        }
    }

    private void swapSymbols(int idx1, int idx2) {
        byte[] data = section.getData();
        int entrySize = is64Bit ? 24 : 16;

        if (idx1 * entrySize + entrySize > data.length || idx2 * entrySize + entrySize > data.length) {
            return;
        }

        byte[] temp = new byte[entrySize];
        int offset1 = idx1 * entrySize;
        int offset2 = idx2 * entrySize;

        System.arraycopy(data, offset1, temp, 0, entrySize);
        System.arraycopy(data, offset2, data, offset1, entrySize);
        System.arraycopy(temp, 0, data, offset2, entrySize);
    }

    /**
     * Symbol class.
     */
    public static class Symbol {
        public final int name;

        public final String nameStr;

        public final long value;

        public final long size;

        public final byte info;

        public final byte other;

        public final short sectionIndex;

        public Symbol(int name, String nameStr, long value, long size, byte info, byte other, short sectionIndex) {
            this.name = name;
            this.nameStr = nameStr;
            this.value = value;
            this.size = size;
            this.info = info;
            this.other = other;
            this.sectionIndex = sectionIndex;
        }

        // Get symbol binding
        public byte getBind() {
            return (byte) (info >> 4);
        }

        // Get symbol type
        public byte getType() {
            return (byte) (info & 0xF);
        }

        // Get symbol visibility
        public byte getVisibility() {
            return (byte) (other & 0x3);
        }

        // Create info from bind and type
        public static byte makeInfo(byte bind, byte type) {
            return (byte) ((bind << 4) | (type & 0xF));
        }

        // Create visibility
        public static byte makeVisibility(byte visibility) {
            return (byte) (visibility & 0x3);
        }
    }
}
