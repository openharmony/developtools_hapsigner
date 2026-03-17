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

    private boolean dataModified = false; // Track if data was modified after loading

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
        // For large sections (>2GB), skip loading to memory to avoid int overflow
        // Data will be streamed directly from source file when needed
        if (size > Integer.MAX_VALUE) {
            // Keep fileChannel reference for streaming
            this.fileChannel = fc;
            this.loadOffset = offset;
            this.data = new byte[0];  // Empty array, data not loaded
            return;
        }

        // Normal case: load into memory
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

    /**
     * Copy section data from source file channel to destination file channel.
     * This is used for zero-copy streaming of large sections.
     *
     * @param dest Destination file channel
     * @param destOffset Offset in destination file
     * @throws IOException if copying fails
     */
    public void copyFromSource(FileChannel dest, long destOffset) throws IOException {
        if (type == ElfTypes.SHT_NOBITS || type == ElfTypes.SHT_NULL || size <= 0) {
            return;
        }

        // If data was modified or loaded into memory, write normally
        if (dataModified || (data != null && data.length > 0)) {
            writeUncompressedData(dest, destOffset);
            return;
        }

        // Stream copy from source file (zero-copy)
        if (fileChannel != null && loadOffset >= 0) {
            long position = loadOffset;
            long remaining = size;
            long destPosition = destOffset;

            // Use FileChannel.transferTo for efficient copying
            while (remaining > 0) {
                // transferTo has a max of Integer.MAX_VALUE bytes per call
                long count = Math.min(remaining, Integer.MAX_VALUE);
                long transferred = fileChannel.transferTo(position, count, dest.position(destPosition));
                if (transferred <= 0) {
                    throw new IOException("Failed to transfer data at position " + position);
                }
                position += transferred;
                destPosition += transferred;
                remaining -= transferred;
            }
        }
    }

    private void writeUncompressedData(FileChannel fc, long dataOffset) throws IOException {
        fc.position(dataOffset);

        // If data was modified or is already loaded, write from memory
        // Note: For large sections (>2GB), dataModified should always be false
        // and data should be empty, so we skip this branch
        if (dataModified || (data != null && data.length > 0)) {
            // Only small sections reach here (size <= Integer.MAX_VALUE)
            if (data.length >= size) {
                ByteBuffer dataBuffer = ByteBuffer.wrap(data, 0, (int) size);
                fc.write(dataBuffer);
            } else {
                // data.length < size, need to pad with zeros
                ByteBuffer dataBuffer = ByteBuffer.wrap(data);
                fc.write(dataBuffer);

                long paddingSize = size - data.length;
                writePadding(fc, paddingSize);
            }
            return;
        }

        // No data in memory, stream from source file
        if (fileChannel != null && loadOffset >= 0 && size > 0) {
            long position = loadOffset;
            long remaining = size;

            // Handle large sections (>2GB) by chunking
            while (remaining > 0) {
                long chunkSize = Math.min(remaining, Integer.MAX_VALUE);
                long transferred = fileChannel.transferTo(position, chunkSize, fc);
                if (transferred <= 0) {
                    throw new IOException("Failed to transfer data at position " + position);
                }
                position += transferred;
                remaining -= transferred;
            }
            return;
        }

        // No data available, write zeros
        writePadding(fc, size);
    }

    /**
     * Write padding bytes (zeros) to file channel.
     *
     * @param fc File channel
     * @param size Number of bytes to write
     * @throws IOException if writing fails
     */
    private void writePadding(FileChannel fc, long size) throws IOException {
        final int BUFFER_SIZE = 8 * 1024 * 1024; // 8MB chunks
        byte[] zeros = new byte[BUFFER_SIZE];
        ByteBuffer buffer = ByteBuffer.wrap(zeros);

        long remaining = size;
        while (remaining > 0) {
            int chunkSize = (int) Math.min(remaining, BUFFER_SIZE);
            buffer.limit(chunkSize);
            buffer.rewind();
            fc.write(buffer);
            remaining -= chunkSize;
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
        // For large sections (>2GB), don't load into memory
        // Return empty array; data will be streamed from source file when saving
        if (size > Integer.MAX_VALUE) {
            return new byte[0];
        }

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

        // Only resize data array if size is within int range and data is not null
        // For large sections (>2GB), data array is not used (streamed from file)
        if (size <= Integer.MAX_VALUE && data != null) {
            this.data = Arrays.copyOf(this.data, (int) size);
        }
        // For large sections (>2GB), keep data as empty array or don't resize
        // Data will be streamed from source file when needed
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
        this.dataModified = true;
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
        // For large sections (>2GB), don't modify in memory
        // Silently ignore; data will be streamed from source file
        if (size > Integer.MAX_VALUE) {
            return;
        }

        // Ensure data is loaded if not already
        if (data == null || data.length == 0) {
            return;  // No data to remove
        }

        if (data.length >= pos + len) {
            byte[] newData = new byte[data.length - len];
            System.arraycopy(data, 0, newData, 0, pos);
            System.arraycopy(data, pos + len, newData, pos, data.length - pos - len);
            data = newData;
            size = data.length;
            dataModified = true;
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

        // For large sections (>2GB), don't modify in memory
        // Silently ignore; data will be streamed from source file
        if (size > Integer.MAX_VALUE) {
            return;
        }

        // Normal case: small section, modify in memory
        byte[] newData = new byte[(int) (size + rawData.length)];
        System.arraycopy(data, 0, newData, 0, (int) pos);
        System.arraycopy(rawData, 0, newData, (int) pos, rawData.length);
        System.arraycopy(data, (int) pos, newData, (int) (pos + rawData.length), (int) (size - pos));

        data = newData;
        size = data.length;
        dataModified = true;
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

    /**
     * Check if data has been modified.
     *
     * @return true if data was modified
     */
    public boolean isDataModified() {
        return dataModified;
    }

    /**
     * Get source file channel (for streaming).
     *
     * @return Source file channel
     */
    public FileChannel getSourceFileChannel() {
        return fileChannel;
    }

    /**
     * Get load offset in source file (for streaming).
     *
     * @return Load offset
     */
    public long getLoadOffset() {
        return loadOffset;
    }

    /**
     * Set source file channel and load offset for a new section.
     * This is used to specify an external data source for a newly created section,
     * allowing zero-copy streaming from another file.
     *
     * @param fc Source file channel containing the section data
     * @param offset Offset in the source file where section data starts
     */
    public void setDataChannel(FileChannel fc, long offset) {
        this.fileChannel = fc;
        this.loadOffset = offset;
        this.data = new byte[0]; // Ensure data array is empty to trigger streaming
    }

    /**
     * Get partial data from section (for large sections).
     *
     * @param offset Offset within section
     * @param length Number of bytes to read
     * @return Partial data
     * @throws IOException if reading fails
     */
    public byte[] getPartialData(long offset, int length) throws IOException {
        if (offset < 0 || length < 0 || offset + length > size) {
            throw new IllegalArgumentException("Invalid offset or length");
        }

        // If data is in memory, return directly
        if (data != null && data.length >= offset + length) {
            byte[] result = new byte[length];
            System.arraycopy(data, (int) offset, result, 0, length);
            return result;
        }

        // Read from file channel
        if (fileChannel != null && loadOffset >= 0) {
            ByteBuffer buffer = ByteBuffer.allocate(length);
            buffer.order(convertor.getByteOrder());
            fileChannel.position(loadOffset + offset);
            fileChannel.read(buffer);
            buffer.flip();
            byte[] result = new byte[length];
            buffer.get(result);
            return result;
        }

        return new byte[0];
    }
}
