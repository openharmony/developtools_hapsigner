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
import java.util.ArrayList;
import java.util.List;

/**
 * ELF program segment (PHDR) representation.
 *
 * @since 2026/3/5
 */
public class Segment {
    private int type;

    private int flags;

    private long offset;

    private long virtualAddress;

    private long physicalAddress;

    private long fileSize;

    private long memorySize;

    private long align;

    private int index;

    private List<Integer> sectionIndices = new ArrayList<>();

    private byte[] data;

    private long streamSize;

    private boolean isLazy;

    private boolean dataModified = false; // Track if data was modified

    private boolean offsetInitialized; // Track if offset was loaded/set from file

    private byte fileClass;

    private ElfioUtils.EndiannessConvertor convertor;

    private ElfioUtils.AddressTranslator addrTranslator;

    /**
     * Create a new segment.
     *
     * @param fileClass ELFCLASS32 or ELFCLASS64
     * @param convertor Endianness convertor
     * @param addrTranslator Address translator
     */
    public Segment(byte fileClass, ElfioUtils.EndiannessConvertor convertor,
        ElfioUtils.AddressTranslator addrTranslator) {
        this.fileClass = fileClass;
        this.convertor = convertor;
        this.addrTranslator = addrTranslator;
    }

    /**
     * Load segment from file.
     *
     * @param fc File channel
     * @param offset Offset in file
     * @throws IOException if reading fails
     */
    public void load(FileChannel fc, long offset) throws IOException {
        int headerSize = (fileClass == ElfTypes.ELFCLASS64) ? 56 : 32;
        ByteBuffer buffer = ByteBuffer.allocate(headerSize);
        buffer.order(convertor.getByteOrder());

        fc.position(offset);
        int bytesRead = fc.read(buffer);
        if (bytesRead < headerSize) {
            throw new IOException("Failed to read segment header");
        }
        buffer.flip();

        this.type = buffer.getInt();

        if (fileClass == ElfTypes.ELFCLASS64) {
            this.flags = buffer.getInt();
            this.offset = buffer.getLong();
            this.virtualAddress = buffer.getLong();
            this.physicalAddress = buffer.getLong();
            this.fileSize = buffer.getLong();
            this.memorySize = buffer.getLong();
            this.align = buffer.getLong();
        } else {
            this.offset = buffer.getInt() & 0xFFFFFFFFL;
            this.virtualAddress = buffer.getInt() & 0xFFFFFFFFL;
            this.physicalAddress = buffer.getInt() & 0xFFFFFFFFL;
            this.fileSize = buffer.getInt() & 0xFFFFFFFFL;
            this.memorySize = buffer.getInt() & 0xFFFFFFFFL;
            this.flags = buffer.getInt();
            this.align = buffer.getInt() & 0xFFFFFFFFL;
        }

        this.offset = addrTranslator.translate(this.offset);
        this.offsetInitialized = true;
    }

    /**
     * Save segment to file.
     *
     * @param fc File channel
     * @param headerOffset Offset for segment header
     * @param dataOffset Offset for segment data (typically same as offset)
     * @throws IOException if writing fails
     */
    public void save(FileChannel fc, long headerOffset, long dataOffset) throws IOException {
        int headerSize = (fileClass == ElfTypes.ELFCLASS64)
            ? ElfTypes.SEGMENT_HEADER_SIZE_64
            : ElfTypes.SEGMENT_HEADER_SIZE_32;
        ByteBuffer buffer = ByteBuffer.allocate(headerSize);
        buffer.order(convertor.getByteOrder());

        buffer.putInt(type);

        if (fileClass == ElfTypes.ELFCLASS64) {
            buffer.putInt(flags);
            buffer.putLong(dataOffset);
            buffer.putLong(virtualAddress);
            buffer.putLong(physicalAddress);
            buffer.putLong(fileSize);
            buffer.putLong(memorySize);
            buffer.putLong(align);
        } else {
            buffer.putInt((int) dataOffset);
            buffer.putInt((int) virtualAddress);
            buffer.putInt((int) physicalAddress);
            buffer.putInt((int) fileSize);
            buffer.putInt((int) memorySize);
            buffer.putInt(flags);
            buffer.putInt((int) align);
        }

        buffer.flip();
        fc.position(headerOffset);
        fc.write(buffer);
    }

    /**
     * Add a section index to this segment.
     *
     * @param sectionIndex The section index
     * @return The new number of sections
     */
    public int addSectionIndex(int sectionIndex) {
        sectionIndices.add(sectionIndex);
        return sectionIndices.size();
    }

    /**
     * Add a section index to this segment with alignment update.
     *
     * @param sectionIndex The section index
     * @param addrAlign Section alignment
     * @return The new number of sections
     */
    public int addSectionIndex(int sectionIndex, long addrAlign) {
        sectionIndices.add(sectionIndex);
        if (addrAlign > align) {
            align = addrAlign;
        }
        return sectionIndices.size();
    }

    /**
     * Add a section to this segment.
     *
     * @param section The section to add
     * @param addrAlign Section alignment
     * @return The new number of sections
     */
    public int addSection(Section section, long addrAlign) {
        return addSectionIndex(section.getIndex(), addrAlign);
    }

    /**
     * Get segment data.
     *
     * @return The segment data
     */
    public byte[] getData() {
        if (isLazy && data == null) {
            loadData();
        }
        return data;
    }

    /**
     * Set segment data.
     *
     * @param data The data to set
     */
    public void setData(byte[] data) {
        this.data = data;
        if (data != null && data.length > 0) {
            this.fileSize = data.length;
        }
        this.dataModified = true;
    }

    /**
     * Get stream size.
     *
     * @return Stream size
     */
    public long getStreamSize() {
        return streamSize;
    }

    /**
     * Set stream size.
     *
     * @param size Stream size
     */
    public void setStreamSize(long size) {
        this.streamSize = size;
    }

    /**
     * Check if lazy loading is enabled.
     *
     * @return true if lazy loading
     */
    public boolean isLazy() {
        return isLazy;
    }

    /**
     * Set lazy loading flag.
     *
     * @param lazy Lazy flag
     */
    public void setLazy(boolean lazy) {
        this.isLazy = lazy;
    }

    private void loadData() {
        isLazy = false;
        // Data would need to be loaded from file channel
        // This is a placeholder - actual implementation would need FileChannel
    }

    /**
     * Sort sections by their file offsets.
     *
     * @param offsets Array of section offsets
     */
    public void sortSections(long[] offsets) {
        sectionIndices.sort((a, b) -> Long.compareUnsigned(offsets[a], offsets[b]));
    }

    // Getters
    public int getType() {
        return type;
    }

    public int getFlags() {
        return flags;
    }

    public long getOffset() {
        return offset;
    }

    public long getVirtualAddress() {
        return virtualAddress;
    }

    public long getPhysicalAddress() {
        return physicalAddress;
    }

    public long getFileSize() {
        return fileSize;
    }

    public long getMemorySize() {
        return memorySize;
    }

    public long getAlign() {
        return align;
    }

    public int getIndex() {
        return index;
    }

    public int getSectionsNum() {
        return sectionIndices.size();
    }

    public List<Integer> getSections() {
        return new ArrayList<>(sectionIndices);
    }

    /**
     * Get section index at position.
     *
     * @param i Position
     * @return Section index
     */
    public int getSectionIndexAt(int i) {
        if (i < 0 || i >= sectionIndices.size()) {
            return 0;
        }
        return sectionIndices.get(i);
    }

    // Setters
    public void setType(int type) {
        this.type = type;
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public void setOffset(long offset) {
        this.offset = offset;
        this.offsetInitialized = true;
    }

    public void setVirtualAddress(long virtualAddress) {
        this.virtualAddress = virtualAddress;
    }

    public void setPhysicalAddress(long physicalAddress) {
        this.physicalAddress = physicalAddress;
    }

    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }

    public void setMemorySize(long memorySize) {
        this.memorySize = memorySize;
    }

    public void setAlign(long align) {
        this.align = align;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    /**
     * Check if offset has been initialized.
     *
     * @return true if offset is set
     */
    public boolean isOffsetInitialized() {
        return offsetInitialized;
    }

    /**
     * Clear all section indices.
     */
    public void clearSections() {
        sectionIndices.clear();
    }

    /**
     * Check if data has been modified.
     *
     * @return true if data was modified
     */
    public boolean isDataModified() {
        return dataModified;
    }

    /**
     * Get partial data from segment (for large segments).
     *
     * @param offset Offset within segment
     * @param length Number of bytes to read
     * @param sections List of all sections (for finding section data)
     * @return Partial data
     * @throws IOException if reading fails
     */
    public byte[] getPartialData(long offset, int length, List<Section> sections) throws IOException {
        if (offset < 0 || length < 0 || offset + length > fileSize) {
            throw new IllegalArgumentException("Invalid offset or length");
        }

        // If data is in memory, return directly
        if (data != null && data.length >= offset + length) {
            byte[] result = new byte[length];
            System.arraycopy(data, (int) offset, result, 0, length);
            return result;
        }

        // If no in-memory data, return empty array
        // (Segment data is typically derived from its sections)
        return new byte[0];
    }

    /**
     * Copy segment data from its sections to destination file channel.
     *
     * @param dest Destination file channel
     * @param destOffset Offset in destination file
     * @param sections List of all sections
     * @param srcFileChannel Source file channel (optional, for streaming)
     * @throws IOException if copying fails
     */
    public void copyDataFromSections(FileChannel dest, long destOffset, List<Section> sections,
                                      FileChannel srcFileChannel) throws IOException {
        if (fileSize <= 0) {
            return;
        }

        dest.position(destOffset);

        // If data is already in memory and modified, write directly
        if (dataModified && data != null && data.length > 0) {
            ByteBuffer buffer = ByteBuffer.wrap(data, 0, (int) Math.min(data.length, fileSize));
            dest.write(buffer);

            // Pad with zeros if needed
            long paddingNeeded = fileSize - data.length;
            if (paddingNeeded > 0) {
                writePadding(dest, paddingNeeded);
            }
            return;
        }

        // Copy data from sections
        long currentOffset = 0L;
        for (int sectionIdx : sectionIndices) {
            if (sectionIdx < 0 || sectionIdx >= sections.size()) {
                continue;
            }

            Section section = sections.get(sectionIdx);
            long sectionOffset = section.getOffset() - this.offset;
            long sectionSize = section.getSize();

            // Skip if section is outside this segment
            if (sectionOffset < 0 || sectionOffset >= fileSize) {
                continue;
            }

            // Write section data
            if (section.getData() != null && section.getData().length > 0) {
                // Write from memory
                int writeLength = (int) Math.min(sectionSize, fileSize - currentOffset);
                byte[] sectionData = section.getData();
                int copyLength = Math.min(writeLength, sectionData.length);
                ByteBuffer buffer = ByteBuffer.wrap(sectionData, 0, copyLength);
                dest.write(buffer);
                currentOffset += copyLength;
            } else if (srcFileChannel != null && section.getSourceFileChannel() != null) {
                // Stream from source file
                long srcOffset = section.getLoadOffset();
                long copySize = Math.min(sectionSize, fileSize - currentOffset);
                long copied = 0L;

                while (copied < copySize) {
                    long chunk = Math.min(copySize - copied, Integer.MAX_VALUE);
                    long transferred = srcFileChannel.transferTo(srcOffset + copied, chunk, dest);
                    if (transferred <= 0) {
                        break;
                    }
                    copied += transferred;
                    currentOffset += transferred;
                }
            }
        }

        // Pad remaining space with zeros
        if (currentOffset < fileSize) {
            writePadding(dest, fileSize - currentOffset);
        }
    }

    /**
     * Write padding bytes (zeros) to file channel.
     *
     * @param fc File channel
     * @param size Number of bytes to write
     * @throws IOException if writing fails
     */
    private void writePadding(FileChannel fc, long size) throws IOException {
        final int bufferSize = 8 * 1024 * 1024; // 8MB chunks
        byte[] zeros = new byte[bufferSize];
        ByteBuffer buffer = ByteBuffer.wrap(zeros);

        long remaining = size;
        while (remaining > 0) {
            int chunkSize = (int) Math.min(remaining, bufferSize);
            buffer.limit(chunkSize);
            buffer.rewind();
            fc.write(buffer);
            remaining -= chunkSize;
        }
    }
}
