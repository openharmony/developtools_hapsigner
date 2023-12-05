/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.hap.entity.zip;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * resolve zip ZipEntryHeader data
 *
 * @since 2023/12/02
 */
class ZipEntryHeader {
    /**
     * ZipEntryHeader invariable bytes length
     */
    public static final int HEADER_LENGTH = 30;

    /**
     * 4 bytes , entry header signature
     */
    public static final int SIGNATURE = 0x04034b50;

    /**
     * 2 bytes
     */
    private short version;

    /**
     * 2 bytes
     */
    private short flag;

    /**
     * 2 bytes
     */
    private short method;

    /**
     * 2 bytes
     */
    private short lastTime;

    /**
     * 2 bytes
     */
    private short lastDate;

    /**
     * 4 bytes
     */
    private int crc32;

    /**
     * 4 bytes
     */
    private int compressedSize;

    /**
     * 4 bytes
     */
    private int unCompressedSize;

    /**
     * 2 bytes
     */
    private short fileNameLength;

    /**
     * 2 bytes
     */
    private short extraLength;

    /**
     * n bytes
     */
    private String fileName;

    /**
     * n bytes
     */
    private byte[] extraData;

    private int length;

    /**
     * init Zip Entry Header
     *
     * @param bytes ZipEntryHeader bytes
     * @return ZipEntryHeader
     */
    public static ZipEntryHeader initZipEntryHeader(byte[] bytes) {
        ZipEntryHeader entryHeader = new ZipEntryHeader();
        ByteBuffer bf = ByteBuffer.allocate(bytes.length);
        bf.put(bytes);
        bf.order(ByteOrder.LITTLE_ENDIAN);
        bf.flip();
        if (bf.getInt() != ZipEntryHeader.SIGNATURE) {
            return null;
        }
        entryHeader.setVersion(bf.getShort());
        entryHeader.setFlag(bf.getShort());
        entryHeader.setMethod(bf.getShort());
        entryHeader.setLastTime(bf.getShort());
        entryHeader.setLastDate(bf.getShort());
        entryHeader.setCrc32(bf.getInt());
        entryHeader.setCompressedSize(bf.getInt());
        entryHeader.setUnCompressedSize(bf.getInt());
        entryHeader.setFileNameLength(bf.getShort());
        entryHeader.setExtraLength(bf.getShort());
        entryHeader.setLength(HEADER_LENGTH + entryHeader.getFileNameLength() + entryHeader.getExtraLength());
        return entryHeader;
    }

    /**
     * set entry header name and extra
     *
     * @param bytes name and extra bytes
     */
    public void setNameAndExtra(byte[] bytes) {
        ByteBuffer bf = ByteBuffer.allocate(bytes.length);
        bf.put(bytes);
        bf.order(ByteOrder.LITTLE_ENDIAN);
        bf.flip();
        if (fileNameLength > 0) {
            byte[] nameBytes = new byte[fileNameLength];
            bf.get(nameBytes);
            this.fileName = new String(nameBytes, StandardCharsets.UTF_8);
        }
        if (extraLength > 0) {
            byte[] extra = new byte[extraLength];
            bf.get(extra);
            this.extraData = extra;
        }
    }

    /**
     * change Zip Entry Header to bytes
     *
     * @return bytes
     */
    public byte[] toBytes() {
        ByteBuffer bf = ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN);
        bf.putInt(SIGNATURE);
        bf.putShort(version);
        bf.putShort(flag);
        bf.putShort(method);
        bf.putShort(lastTime);
        bf.putShort(lastDate);
        bf.putInt(crc32);
        bf.putInt(compressedSize);
        bf.putInt(unCompressedSize);
        bf.putShort(fileNameLength);
        bf.putShort(extraLength);
        if (fileNameLength > 0) {
            bf.put(fileName.getBytes(StandardCharsets.UTF_8));
        }
        if (extraLength > 0) {
            bf.put(extraData);
        }
        return bf.array();
    }

    public short getFlag() {
        return flag;
    }

    public void setFlag(short flag) {
        this.flag = flag;
    }

    public short getMethod() {
        return method;
    }

    public void setMethod(short method) {
        this.method = method;
    }

    public short getVersion() {
        return version;
    }

    public void setVersion(short version) {
        this.version = version;
    }

    public short getLastTime() {
        return lastTime;
    }

    public void setLastTime(short lastTime) {
        this.lastTime = lastTime;
    }

    public short getLastDate() {
        return lastDate;
    }

    public void setLastDate(short lastDate) {
        this.lastDate = lastDate;
    }

    public int getCrc32() {
        return crc32;
    }

    public void setCrc32(int crc32) {
        this.crc32 = crc32;
    }

    public int getCompressedSize() {
        return compressedSize;
    }

    public void setCompressedSize(int compressedSize) {
        this.compressedSize = compressedSize;
    }

    public int getUnCompressedSize() {
        return unCompressedSize;
    }

    public void setUnCompressedSize(int unCompressedSize) {
        this.unCompressedSize = unCompressedSize;
    }

    public short getFileNameLength() {
        return fileNameLength;
    }

    public void setFileNameLength(short fileNameLength) {
        this.fileNameLength = fileNameLength;
    }

    public short getExtraLength() {
        return extraLength;
    }

    public void setExtraLength(short extraLength) {
        this.extraLength = extraLength;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public byte[] getExtraData() {
        return extraData;
    }

    public void setExtraData(byte[] extraData) {
        this.extraData = extraData;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }
}