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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

/**
 * ELF file header.
 *
 * @since 2026/3/5
 */
public class ElfHeader {
    private byte fileClass;

    private byte encoding;

    private byte elfVersion;

    private byte osAbi;

    private byte abiVersion;

    private short type;

    private short machine;

    private int version;

    private long entry;

    private long segmentsOffset;

    private long sectionsOffset;

    private int flags;

    private short headerSize;

    private short segmentEntrySize;

    private short segmentNum;

    private short sectionEntrySize;

    private short sectionNum;

    private short sectionNameStrIndex;

    private ElfioUtils.EndiannessConvertor convertor;

    private ElfioUtils.AddressTranslator addrTranslator;

    /**
     * Create a new ELF header.
     */
    public ElfHeader() {
        // Default values
        fileClass = ElfTypes.ELFCLASS32;
        encoding = ElfTypes.ELFDATA2LSB;
        elfVersion = ElfTypes.EV_CURRENT;
        type = ElfTypes.ET_REL;
        machine = ElfTypes.EM_NONE;
        version = 1;
        convertor = new ElfioUtils.EndiannessConvertor();
        addrTranslator = new ElfioUtils.AddressTranslator();
    }

    /**
     * Load the ELF header from a file channel.
     *
     * @param fc The file channel
     * @throws IOException if reading fails
     */
    public void load(FileChannel fc) throws IOException {
        int size = (fileClass == ElfTypes.ELFCLASS64) ? ElfTypes.HEADER_SIZE_64 : ElfTypes.HEADER_SIZE_32;
        ByteBuffer buffer = ByteBuffer.allocate(size);
        buffer.order(convertor.getByteOrder());

        fc.position(0);
        int bytesRead = fc.read(buffer);
        if (bytesRead < size) {
            throw new IOException("Failed to read ELF header");
        }
        buffer.flip();

        // Skip e_ident (first 16 bytes) - we already read it
        buffer.position(16);

        // Read remaining header fields
        type = buffer.getShort();
        machine = buffer.getShort();
        version = buffer.getInt();

        if (fileClass == ElfTypes.ELFCLASS64) {
            entry = buffer.getLong();
            segmentsOffset = buffer.getLong();
            sectionsOffset = buffer.getLong();
        } else {
            entry = buffer.getInt() & 0xFFFFFFFFL;
            segmentsOffset = buffer.getInt() & 0xFFFFFFFFL;
            sectionsOffset = buffer.getInt() & 0xFFFFFFFFL;
        }

        flags = buffer.getInt();
        if (size != buffer.getShort()) {
            throw new IOException("Failed to compare ELF header size");
        }
        segmentEntrySize = buffer.getShort();
        segmentNum = buffer.getShort();
        sectionEntrySize = buffer.getShort();
        sectionNum = buffer.getShort();
        sectionNameStrIndex = buffer.getShort();
    }

    /**
     * Save the ELF header to a file channel.
     *
     * @param fc The file channel
     * @throws IOException if writing fails
     */
    public void save(FileChannel fc) throws IOException {
        int size = (fileClass == ElfTypes.ELFCLASS64) ? ElfTypes.HEADER_SIZE_64 : ElfTypes.HEADER_SIZE_32;

        ByteBuffer buffer = ByteBuffer.allocate(size);
        buffer.order(convertor.getByteOrder());

        // Write e_ident
        buffer.put((byte) 0x7F); // ELFMAG0
        buffer.put((byte) 'E');  // ELFMAG1
        buffer.put((byte) 'L');  // ELFMAG2
        buffer.put((byte) 'F');  // ELFMAG3
        buffer.put(fileClass);
        buffer.put(encoding);
        buffer.put(elfVersion);
        buffer.put(osAbi);
        buffer.put(abiVersion);
        // Pad rest of e_ident
        for (int i = 9; i < 16; i++) {
            buffer.put((byte) 0);
        }

        buffer.putShort(type);
        buffer.putShort(machine);
        buffer.putInt(version);

        if (fileClass == ElfTypes.ELFCLASS64) {
            buffer.putLong(entry);
            buffer.putLong(segmentsOffset);
            buffer.putLong(sectionsOffset);
        } else {
            buffer.putInt((int) entry);
            buffer.putInt((int) segmentsOffset);
            buffer.putInt((int) sectionsOffset);
        }

        buffer.putInt(flags);
        buffer.putShort(this.headerSize);
        buffer.putShort(segmentEntrySize);
        buffer.putShort(segmentNum);
        buffer.putShort(sectionEntrySize);
        buffer.putShort(sectionNum);
        buffer.putShort(sectionNameStrIndex);

        buffer.flip();
        fc.position(0);
        fc.write(buffer);
    }

    // Getters
    public byte getFileClass() {
        return fileClass;
    }

    public byte getEncoding() {
        return encoding;
    }

    public byte getElfVersion() {
        return elfVersion;
    }

    public byte getOsAbi() {
        return osAbi;
    }

    public byte getAbiVersion() {
        return abiVersion;
    }

    public short getType() {
        return type;
    }

    public short getMachine() {
        return machine;
    }

    public int getVersion() {
        return version;
    }

    public long getEntry() {
        return entry;
    }

    public long getSegmentsOffset() {
        return segmentsOffset;
    }

    public long getSectionsOffset() {
        return sectionsOffset;
    }

    public int getFlags() {
        return flags;
    }

    public short getHeaderSize() {
        return headerSize;
    }

    public short getSegmentEntrySize() {
        return segmentEntrySize;
    }

    public short getSegmentNum() {
        return segmentNum;
    }

    public short getSectionEntrySize() {
        return sectionEntrySize;
    }

    public short getSectionNum() {
        return sectionNum;
    }

    public short getSectionNameStrIndex() {
        return sectionNameStrIndex;
    }

    public ElfioUtils.EndiannessConvertor getConvertor() {
        return convertor;
    }

    public ElfioUtils.AddressTranslator getAddrTranslator() {
        return addrTranslator;
    }

    // Setters
    public void setFileClass(byte fileClass) {
        this.fileClass = fileClass;
        updateHeaderSize();
    }

    public void setEncoding(byte encoding) {
        this.encoding = encoding;
        convertor.setup(encoding);
    }

    public void setElfVersion(byte elfVersion) {
        this.elfVersion = elfVersion;
    }

    public void setOsAbi(byte osAbi) {
        this.osAbi = osAbi;
    }

    public void setAbiVersion(byte abiVersion) {
        this.abiVersion = abiVersion;
    }

    public void setType(short type) {
        this.type = type;
    }

    public void setMachine(short machine) {
        this.machine = machine;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public void setEntry(long entry) {
        this.entry = entry;
    }

    public void setSegmentsOffset(long segmentsOffset) {
        this.segmentsOffset = segmentsOffset;
    }

    public void setSectionsOffset(long sectionsOffset) {
        this.sectionsOffset = sectionsOffset;
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public void setSegmentEntrySize(short segmentEntrySize) {
        this.segmentEntrySize = segmentEntrySize;
    }

    public void setSegmentNum(short segmentNum) {
        this.segmentNum = segmentNum;
    }

    public void setSectionEntrySize(short sectionEntrySize) {
        this.sectionEntrySize = sectionEntrySize;
    }

    public void setSectionNum(short sectionNum) {
        this.sectionNum = sectionNum;
    }

    public void setSectionNameStrIndex(short sectionNameStrIndex) {
        this.sectionNameStrIndex = sectionNameStrIndex;
    }

    private void updateHeaderSize() {
        headerSize = (fileClass == ElfTypes.ELFCLASS64) ? ElfTypes.HEADER_SIZE_64 : ElfTypes.HEADER_SIZE_32;
    }
}
