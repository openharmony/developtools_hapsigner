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
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Standard implementation of CompressionInterface using zlib.
 * Supports compression and decompression of ELF sections.
 *
 * @since 2026/3/5
 */
public class ZlibCompression implements ElfioUtils.CompressionInterface {
    @Override
    public CompressionResult inflate(byte[] data, ElfioUtils.EndiannessConvertor convertor, long compressedSize)
        throws IOException {
        if (data == null || data.length == 0) {
            return new CompressionResult(new byte[0], 0);
        }

        // Check for ELF compression header (ELF compression format)
        int headerSize = 0;
        int chType = 0;

        // Try to read compression header
        if (data.length >= 12) {
            ByteBuffer header = ByteBuffer.wrap(data, 0, 12);
            header.order(convertor.getByteOrder());

            chType = header.getInt();
            if (chType == 1 || chType == 2) { // ZLIB or other compression type
                if (convertor.getByteOrder() == ByteOrder.BIG_ENDIAN) {
                    header.getInt();
                    header.getInt();
                } else {
                    header.getInt();
                }
                if (convertor.getByteOrder() != ByteOrder.BIG_ENDIAN) {
                    header.getInt();
                }
                headerSize = 12;
            }
        }

        // Skip header if present
        byte[] compressedData;
        if (headerSize > 0) {
            compressedData = new byte[data.length - headerSize];
            System.arraycopy(data, headerSize, compressedData, 0, compressedData.length);
        } else {
            compressedData = data;
        }

        // Decompress using zlib
        Inflater inflater = new Inflater(true); // Use zlib header
        inflater.setInput(compressedData);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(compressedData.length);
        byte[] buffer = new byte[8192];

        try {
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                outputStream.write(buffer, 0, count);
            }
            outputStream.close();
        } catch (DataFormatException e) {
            throw new IOException("Decompression failed", e);
        } finally {
            inflater.end();
        }

        byte[] result = outputStream.toByteArray();
        return new CompressionResult(result, result.length);
    }

    @Override
    public CompressionResult deflate(byte[] data, ElfioUtils.EndiannessConvertor convertor, long decompressedSize)
        throws IOException {
        if (data == null || data.length == 0) {
            return new CompressionResult(new byte[0], 0);
        }

        // Compress using zlib
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true); // Use zlib header
        deflater.setInput(data);
        deflater.finish();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[8192];

        int compressedSize;
        while (!deflater.finished()) {
            compressedSize = deflater.deflate(buffer);
            outputStream.write(buffer, 0, compressedSize);
        }
        outputStream.close();
        deflater.end();

        byte[] compressed = outputStream.toByteArray();

        // Add ELF compression header
        ByteBuffer header = ByteBuffer.allocate(12);
        header.order(convertor.getByteOrder());
        header.putInt(1); // ch_type = ZLIB

        if (convertor.getByteOrder() == ByteOrder.BIG_ENDIAN) {
            header.putInt((int) (decompressedSize >> 32));
            header.putInt((int) decompressedSize);
            header.putInt(8); // ch_addralign (typical alignment)
        } else {
            header.putInt((int) decompressedSize);
            header.putInt(8); // ch_addralign
            // 32-bit has different layout
        }

        byte[] headerBytes = header.array();

        // Combine header and compressed data
        byte[] result = new byte[headerBytes.length + compressed.length];
        System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
        System.arraycopy(compressed, 0, result, headerBytes.length, compressed.length);

        return new CompressionResult(result, result.length);
    }
}
