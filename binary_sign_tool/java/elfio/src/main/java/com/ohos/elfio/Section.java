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
import java.util.Arrays;

/**
 * ELF section representation.
 *
 * @since 2026/3/5
 */
public class Section {
    private int name;

    private int type;

    private long flags;

    private long address;

    private long offset;

    private long size;

    private int link;

    private int info;

    private long addralign;

    private long entsize;

    private String nameStr = "";

    private byte[] data;

    private int index;

    private long streamSize;

    private boolean isLazy;

    private FileChannel fileChannel; // For lazy loading

    private long loadOffset;         // Offset for lazy loading

    private boolean addressInitialized; // Track if address was explicitly set

    private boolean offsetSet = false; // Track if offset was explicitly set

    private Elfio parentElfio;       // Reference to parent Elfio for offset recalculation

    private byte fileClass;

    private ElfioUtils.EndiannessConvertor convertor;

    private ElfioUtils.AddressTranslator addrTranslator;

    private ElfioUtils.CompressionInterface compression;

    /**
     * Create a new section.
     *
     * @param fileClass ELFCLASS32 or ELFCLASS64
     * @param convertor Endianness convertor
     * @param addrTranslator Address translator
     * @param compression Compression interface (can be null)
     */
    public Section(byte fileClass, ElfioUtils.EndiannessConvertor convertor,
        ElfioUtils.AddressTranslator addrTranslator, ElfioUtils.CompressionInterface compression) {
        this.fileClass = fileClass;
        this.convertor = convertor;
        this.addrTranslator = addrTranslator;
        this.compression = compression;
        this.data = new byte[0];
    }

    /**
     * Load section from file.
     *
     * @param fc File channel
     * @param offset Offset in file
     * @throws IOException if reading fails
     */
    public void load(FileChannel fc, long offset) throws IOException {
        int headerSize = (fileClass == ElfTypes.ELFCLASS64)
            ? ElfTypes.SECTION_HEADER_SIZE_64
            : ElfTypes.SECTION_HEADER_SIZE_32;
        ByteBuffer buffer = ByteBuffer.allocate(headerSize);
        buffer.order(convertor.getByteOrder());

        fc.position(offset);
        int bytesRead = fc.read(buffer);
        if (bytesRead < headerSize) {
            throw new IOException("Failed to read section header");
        }
        buffer.flip();

        this.name = buffer.getInt();
        this.type = buffer.getInt();
        this.flags = (fileClass == ElfTypes.ELFCLASS64) ? buffer.getLong() : (buffer.getInt() & 0xFFFFFFFFL);

        if (fileClass == ElfTypes.ELFCLASS64) {
            this.address = buffer.getLong();
            this.offset = buffer.getLong();
            this.size = buffer.getLong();
        } else {
            this.address = buffer.getInt() & 0xFFFFFFFFL;
            this.offset = buffer.getInt() & 0xFFFFFFFFL;
            this.size = buffer.getInt() & 0xFFFFFFFFL;
        }

        this.link = buffer.getInt();
        this.info = buffer.getInt();

        if (fileClass == ElfTypes.ELFCLASS64) {
            this.addralign = buffer.getLong();
            this.entsize = buffer.getLong();
        } else {
            this.addralign = buffer.getInt() & 0xFFFFFFFFL;
            this.entsize = buffer.getInt() & 0xFFFFFFFFL;
        }

        // Load section data if not NOBITS
        if (type != ElfTypes.SHT_NOBITS && type != ElfTypes.SHT_NULL && this.size > 0) {
            this.fileChannel = fc;
            this.loadOffset = addrTranslator.translate(this.offset);

            // If lazy loading is disabled, load data immediately
            if (!isLazy) {
                loadData();
            }
        }
    }

    /**
     * Load data from file (used for lazy loading).
     *
     * @throws IOException if reading fails
     */
    private void loadData() throws IOException {
        if (fileChannel == null || data != null && data.length > 0) {
            return;
        }

        loadData(fileChannel, loadOffset);

        // Handle decompression if needed
        if (isCompressed() && compression != null) {
            ElfioUtils.CompressionInterface.CompressionResult result = compression.inflate(data, convertor, size);
            if (result != null && result.data != null) {
                data = result.data;
                size = result.size;
            }
        }

        isLazy = false;
    }

    private void loadData(FileChannel fc, long offset) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate((int) size);
        buffer.order(convertor.getByteOrder());
        fc.position(offset);
        int bytesRead = fc.read(buffer);
        if (bytesRead < size) {
            throw new IOException("Failed to read section data");
        }
        buffer.flip();
        data = new byte[(int) size];
        buffer.get(data);
    }

    /**
     * Save section to file.
     *
     * @param fc File channel
     * @param headerOffset Offset for section header
     * @param dataOffset Offset for section data
     * @throws IOException if writing fails
     */
    public void save(FileChannel fc, long headerOffset, long dataOffset) throws IOException {
        writeSectionHeader(fc, headerOffset, dataOffset);
        writeSectionBody(fc, dataOffset);
    }

    private void writeSectionHeader(FileChannel fc, long headerOffset, long dataOffset) throws IOException {
        int headerSize = (fileClass == ElfTypes.ELFCLASS64)
            ? ElfTypes.SECTION_HEADER_SIZE_64
            : ElfTypes.SECTION_HEADER_SIZE_32;
        ByteBuffer buffer = ByteBuffer.allocate(headerSize);
        buffer.order(convertor.getByteOrder());

        long offsetToWrite = (index != 0) ? dataOffset : 0;
        buffer.putInt(name);
        buffer.putInt(type);
        if (fileClass == ElfTypes.ELFCLASS64) {
            buffer.putLong(flags);
            buffer.putLong(address);
            buffer.putLong(offsetToWrite);
            buffer.putLong(size);
        } else {
            buffer.putInt((int) flags);
            buffer.putInt((int) address);
            buffer.putInt((int) offsetToWrite);
            buffer.putInt((int) size);
        }
        buffer.putInt(link);
        buffer.putInt(info);
        if (fileClass == ElfTypes.ELFCLASS64) {
            buffer.putLong(addralign);
            buffer.putLong(entsize);
        } else {
            buffer.putInt((int) addralign);
            buffer.putInt((int) entsize);
        }
        buffer.flip();
        fc.position(headerOffset);
        fc.write(buffer);
    }

    private void writeSectionBody(FileChannel fc, long dataOffset) throws IOException {
        if (type == ElfTypes.SHT_NOBITS || type == ElfTypes.SHT_NULL || size <= 0) {
            return;
        }
        boolean compressed = (flags & ElfTypes.SHF_COMPRESSED) != 0 || (flags & ElfTypes.SHF_RPX_DEFLATE) != 0;
        if (!compressed) {
            writeUncompressedData(fc, dataOffset);
            return;
        }
        if (compression == null || data == null) {
            writeUncompressedData(fc, dataOffset);
            return;
        }
        try {
            ElfioUtils.CompressionInterface.CompressionResult result = compression.deflate(data, convertor, size);
            ByteBuffer dataBuffer = ByteBuffer.wrap(result.data);
            fc.position(dataOffset);
            fc.write(dataBuffer);
        } catch (IOException e) {
            writeUncompressedData(fc, dataOffset);
        }
    }

    private void writeUncompressedData(FileChannel fc, long dataOffset) throws IOException {
        fc.position(dataOffset);
        if (data != null) {
            if (data.length >= size) {
                ByteBuffer dataBuffer = ByteBuffer.wrap(data, 0, (int) size);
                fc.write(dataBuffer);
            } else {
                // data.length < size, need to pad with zeros
                ByteBuffer dataBuffer = ByteBuffer.wrap(data);
                fc.write(dataBuffer);

                int paddingSize = (int) (size - data.length);
                ByteBuffer padding = ByteBuffer.allocate(paddingSize);
                // ByteBuffer is already zeroed
                fc.write(padding);
            }
        } else {
            // No data but size > 0, write all zeros
            ByteBuffer padding = ByteBuffer.allocate((int) size);
            fc.write(padding);
        }
    }

    // Getters
    public String getName() {
        return nameStr;
    }

    public int getType() {
        return type;
    }

    public long getFlags() {
        return flags;
    }

    public long getAddress() {
        return address;
    }

    public long getOffset() {
        return offset;
    }

    public long getSize() {
        return size;
    }

    public int getLink() {
        return link;
    }

    public int getInfo() {
        return info;
    }

    public long getAddrAlign() {
        return addralign;
    }

    public long getEntSize() {
        return entsize;
    }

    public int getIndex() {
        return index;
    }

    public byte[] getData() {
        // Lazy loading: load data if not already loaded
        if (isLazy && (data == null || data.length == 0) && fileChannel != null) {
            try {
                loadData();
            } catch (IOException e) {
                // Return empty array on failure
                return new byte[0];
            }
        }
        return data;
    }

    // Setters
    public void setName(String name) {
        this.nameStr = name;
    }

    public void setType(int type) {
        this.type = type;
    }

    public void setFlags(long flags) {
        this.flags = flags;
    }

    public void setAddress(long address) {
        this.address = address;
        this.addressInitialized = true;
    }

    public void setOffset(long offset) {
        this.offset = offset;
        this.offsetSet = true;
    }

    public void setSize(long size) {
        this.size = size;
        this.data = Arrays.copyOf(this.data, (int) size);
    }

    public void setLink(int link) {
        this.link = link;
    }

    public void setInfo(int info) {
        this.info = info;
    }

    public void setAddrAlign(long addralign) {
        this.addralign = addralign;
        // If this is a newly added section (not from loaded file) and offset was set,
        // trigger offset recalculation to respect new alignment
        if (offsetSet && !addressInitialized && parentElfio != null) {
            parentElfio.realignSection(this);
        }
    }

    public void setEntSize(long entsize) {
        this.entsize = entsize;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public void setData(byte[] data) {
        this.data = data;
        this.size = data.length;
    }

    /**
     * Set parent Elfio reference for offset recalculation.
     *
     * @param parent The parent Elfio instance
     */
    void setParentElfio(Elfio parent) {
        this.parentElfio = parent;
    }

    /**
     * Set name string offset for section header.
     *
     * @param offset Offset in string table
     */
    public void setNameStringOffset(int offset) {
        this.name = offset;
    }

    /**
     * Get name string offset for section header.
     *
     * @return Offset in string table
     */
    public int getNameStringOffset() {
        return name;
    }

    /**
     * Check if address has been initialized.
     *
     * @return true if address is set
     */
    public boolean isAddressInitialized() {
        return addressInitialized;
    }

    /**
     * Check if offset has been initialized.
     *
     * @return true if offset is set
     */
    public boolean isOffsetInitialized() {
        return offset != 0;
    }

    /**
     * Remove data from section.
     *
     * @param pos Starting position
     * @param len Length to remove
     */
    public void removeData(int pos, int len) {
        if (data.length >= pos + len) {
            byte[] newData = new byte[data.length - len];
            System.arraycopy(data, 0, newData, 0, pos);
            System.arraycopy(data, pos + len, newData, pos, data.length - pos - len);
            data = newData;
            size = data.length;
        }
    }

    /**
     * Append data to the section.
     *
     * @param rawData Data to append
     */
    public void appendData(byte[] rawData) {
        if (type == ElfTypes.SHT_NOBITS) {
            return;
        }
        insertData(size, rawData);
    }

    /**
     * Append data to the section.
     *
     * @param rawData Data to append
     * @param len Length of data
     */
    public void appendData(byte[] rawData, int len) {
        if (rawData == null || len <= 0) {
            return;
        }
        int actualLen = Math.min(len, rawData.length);
        insertData(size, Arrays.copyOf(rawData, actualLen));
    }

    /**
     * Insert data at the specified position.
     *
     * @param pos Position to insert at
     * @param rawData Data to insert
     */
    public void insertData(long pos, byte[] rawData) {
        if (type == ElfTypes.SHT_NOBITS) {
            return;
        }
        if (rawData == null || rawData.length == 0) {
            return;
        }
        if (pos > size || pos < 0) {
            return;
        }

        byte[] newData = new byte[(int) (size + rawData.length)];
        System.arraycopy(data, 0, newData, 0, (int) pos);
        System.arraycopy(rawData, 0, newData, (int) pos, rawData.length);
        System.arraycopy(data, (int) pos, newData, (int) (pos + rawData.length), (int) (size - pos));

        data = newData;
        size = data.length;
    }

    /**
     * Get entry size (alias for getEntSize for consistency).
     *
     * @return Entry size
     */
    public long getEntrySize() {
        return entsize;
    }

    /**
     * Check if the section is compressed.
     *
     * @return true if section is compressed
     */
    public boolean isCompressed() {
        return ((flags & ElfTypes.SHF_COMPRESSED) != 0 || (flags & ElfTypes.SHF_RPX_DEFLATE) != 0)
            && compression != null;
    }

    /**
     * Get stream size (for lazy loading).
     *
     * @return Stream size
     */
    public long getStreamSize() {
        return streamSize;
    }

    /**
     * Set stream size (for lazy loading).
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
}
