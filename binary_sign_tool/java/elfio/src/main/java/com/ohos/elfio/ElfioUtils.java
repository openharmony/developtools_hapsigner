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
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * ELFIO utility classes and functions.
 *
 * @since 2026/3/5
 */
public class ElfioUtils {

    // Private constructor to prevent instantiation
    private ElfioUtils() {
    }

    /**
     * Endianness converter for ELF file data.
     */
    public static class EndiannessConvertor {
        private boolean needConversion = false;

        private ByteOrder byteOrder;

        /**
         * Set up the converter based on ELF file encoding.
         *
         * @param elfFileEncoding The ELF data encoding (ELFDATA2LSB or ELFDATA2MSB)
         */
        public void setup(byte elfFileEncoding) {
            needConversion = (elfFileEncoding != getHostEncoding());
            byteOrder = (elfFileEncoding == ElfTypes.ELFDATA2LSB) ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;
        }

        /**
         * Get the ByteOrder for ByteBuffer operations.
         *
         * @return The byte order
         */
        public ByteOrder getByteOrder() {
            return byteOrder;
        }

        /**
         * Check if conversion is needed.
         *
         * @return true if byte order conversion is needed
         */
        public boolean needsConversion() {
            return needConversion;
        }

        /**
         * Convert a 16-bit value.
         *
         * @param value The value to convert
         * @return The converted value
         */
        public short convert(short value) {
            if (!needConversion) {
                return value;
            }
            return Short.reverseBytes(value);
        }

        /**
         * Convert a 32-bit value.
         *
         * @param value The value to convert
         * @return The converted value
         */
        public int convert(int value) {
            if (!needConversion) {
                return value;
            }
            return Integer.reverseBytes(value);
        }

        /**
         * Convert a 64-bit value.
         *
         * @param value The value to convert
         * @return The converted value
         */
        public long convert(long value) {
            if (!needConversion) {
                return value;
            }
            return Long.reverseBytes(value);
        }

        /**
         * Get the host system's endianness.
         *
         * @return ELFDATA2LSB or ELFDATA2MSB
         */
        private byte getHostEncoding() {
            ByteBuffer tester = ByteBuffer.allocate(2);
            tester.order(ByteOrder.nativeOrder());
            tester.putShort((short) 0x0102);
            byte[] bytes = tester.array();
            return (bytes[0] == 0x02) ? ElfTypes.ELFDATA2LSB : ElfTypes.ELFDATA2MSB;
        }
    }

    /**
     * Address translation entry.
     */
    public static class AddressTranslation {
        public final long start;

        public final long size;

        public final long mappedTo;

        public AddressTranslation(long start, long size, long mappedTo) {
            this.start = start;
            this.size = size;
            this.mappedTo = mappedTo;
        }
    }

    /**
     * Address translator for mapping virtual to physical addresses.
     */
    public static class AddressTranslator {
        private List<AddressTranslation> addrTranslations = new ArrayList<>();

        /**
         * Set the address translation table.
         *
         * @param addrTrans List of address translations
         */
        public void setAddressTranslation(List<AddressTranslation> addrTrans) {
            addrTranslations = new ArrayList<>(addrTrans);
            Collections.sort(addrTranslations, (a, b) -> Long.compareUnsigned(a.start, b.start));
        }

        /**
         * Translate an address.
         *
         * @param value The address to translate
         * @return The translated address
         */
        public long translate(long value) {
            if (addrTranslations.isEmpty()) {
                return value;
            }

            for (AddressTranslation t : addrTranslations) {
                if (t.start <= value && (value - t.start) < t.size) {
                    return value - t.start + t.mappedTo;
                }
            }

            return value;
        }

        /**
         * Check if translation table is empty.
         *
         * @return true if empty
         */
        public boolean isEmpty() {
            return addrTranslations.isEmpty();
        }
    }

    /**
     * Compute ELF hash.
     *
     * @param name The string to hash
     * @return The hash value
     */
    public static int elfHash(String name) {
        int h = 0;
        int g = 0;

        byte[] bytes = name.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        for (byte b : bytes) {
            if (b == 0) {
                break;
            }
            h = (h << 4) + (b & 0xFF);
            g = h & 0xf0000000;
            if (g != 0) {
                h ^= g >>> 24;
            }
            h &= ~g;
        }

        return h;
    }

    /**
     * Compute GNU ELF hash.
     *
     * @param name The string to hash
     * @return The hash value
     */
    public static int elfGnuHash(String name) {
        int h = 0x1505;
        byte[] bytes = name.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        for (byte b : bytes) {
            if (b == 0) {
                break;
            }
            h = (h << 5) + h + (b & 0xFF);
        }
        return h;
    }

    /**
     * Convert value to hex string.
     *
     * @param value The value to convert
     * @return Hex string with "0x" prefix
     */
    public static String toHexString(long value) {
        if (value == 0) {
            return "0x0";
        }
        return "0x" + Long.toHexString(value);
    }

    /**
     * Compression interface for handling compressed sections.
     */
    public interface CompressionInterface {
        /**
         * Decompress a compressed section.
         *
         * @param data The compressed data
         * @param convertor Endianness convertor
         * @param compressedSize Size of compressed data
         * @return Array containing decompressed data and size info
         * @throws IOException if decompression fails
         */
        CompressionResult inflate(byte[] data, EndiannessConvertor convertor, long compressedSize) throws IOException;

        /**
         * Compress a section.
         *
         * @param data The uncompressed data
         * @param convertor Endianness convertor
         * @param decompressedSize Size of uncompressed data
         * @return Array containing compressed data and size info
         * @throws IOException if compression fails
         */
        CompressionResult deflate(byte[] data, EndiannessConvertor convertor, long decompressedSize) throws IOException;

        /**
         * Result of compression/decompression operation.
         */
        class CompressionResult {
            public final byte[] data;

            public final long size;

            public CompressionResult(byte[] data, long size) {
                this.data = data;
                this.size = size;
            }
        }
    }
}
