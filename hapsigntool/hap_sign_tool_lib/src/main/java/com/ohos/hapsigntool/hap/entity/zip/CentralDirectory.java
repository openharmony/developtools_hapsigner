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

import com.ohos.hapsigntool.error.ZipException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * resolve zip CentralDirectory data
 *
 * @since 2023/12/02
 */
class CentralDirectory {
    /**
     * central directory invariable bytes length
     */
    public static final int CD_LENGTH = 46;

    /**
     * 4 bytes , central directory signature
     */
    public static final int SIGNATURE = 0x02014b50;

    /**
     * 2 bytes
     */
    private short version;

    /**
     * 2 bytes
     */
    private short versionExtra;


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
     * 2 bytes
     */
    private short commentLength;

    /**
     * 2 bytes
     */
    private short diskNumStart;


    /**
     * 2 bytes
     */
    private short internalFile;


    /**
     * 4 bytes
     */
    private int externalFile;


    /**
     * 4 bytes
     */
    private int offset;

    /**
     * n bytes
     */
    private String fileName;

    /**
     * n bytes
     */
    private byte[] extraData;

    /**
     * n bytes
     */
    private String comment;

    private int length;

    /**
     * init Central Directory
     *
     * @param bytes Full Central Directory bytes
     * @param offset One Central Directory offset
     * @return CentralDirectory
     * @throws ZipException read Central Directory exception
     */
    public static CentralDirectory initCentralDirectory(byte[] bytes, int offset) throws ZipException {
        if (bytes.length < offset) {
            throw new ZipException("find zip central directory failed");
        }
        CentralDirectory cd = new CentralDirectory();
        int byteLength = bytes.length - offset;
        ByteBuffer bf = ByteBuffer.allocate(byteLength);
        bf.put(bytes, offset, byteLength);
        bf.order(ByteOrder.LITTLE_ENDIAN);
        bf.flip();
        if (bf.getInt() != SIGNATURE) {
            throw new ZipException("find zip central directory failed");
        }
        cd.setVersion(bf.getShort());
        cd.setVersionExtra(bf.getShort());
        cd.setFlag(bf.getShort());
        cd.setMethod(bf.getShort());
        cd.setLastTime(bf.getShort());
        cd.setLastDate(bf.getShort());
        cd.setCrc32(bf.getInt());
        cd.setCompressedSize(bf.getInt());
        cd.setUnCompressedSize(bf.getInt());
        cd.setFileNameLength(bf.getShort());
        cd.setExtraLength(bf.getShort());
        cd.setCommentLength(bf.getShort());
        cd.setDiskNumStart(bf.getShort());
        cd.setInternalFile(bf.getShort());
        cd.setExternalFile(bf.getInt());
        cd.setOffset(bf.getInt());
        if (cd.getFileNameLength() > 0) {
            byte[] readFileName = new byte[cd.getFileNameLength()];
            bf.get(readFileName);
            cd.setFileName(new String(readFileName, StandardCharsets.UTF_8));
        }
        if (cd.getExtraLength() > 0) {
            byte[] extra = new byte[cd.getExtraLength()];
            bf.get(extra);
            cd.setExtraData(extra);
        }
        if (cd.getCommentLength() > 0) {
            byte[] readComment = new byte[cd.getCommentLength()];
            bf.get(readComment);
            cd.setComment(new String(readComment, StandardCharsets.UTF_8));
        }
        cd.setLength(byteLength);
        return cd;
    }

    /**
     * change Central Directory to bytes
     *
     * @return bytes
     */
    public byte[] toBytes() {
        ByteBuffer bf = ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN);
        bf.putInt(SIGNATURE);
        bf.putShort(version);
        bf.putShort(versionExtra);
        bf.putShort(flag);
        bf.putShort(method);
        bf.putShort(lastTime);
        bf.putShort(lastDate);
        bf.putInt(crc32);
        bf.putInt(compressedSize);
        bf.putInt(unCompressedSize);
        bf.putShort(fileNameLength);
        bf.putShort(extraLength);
        bf.putShort(commentLength);
        bf.putShort(diskNumStart);
        bf.putShort(internalFile);
        bf.putInt(externalFile);
        bf.putInt(offset);
        if (fileNameLength > 0) {
            bf.put(fileName.getBytes(StandardCharsets.UTF_8));
        }
        if (extraLength > 0) {
            bf.put(extraData);
        }
        if (commentLength > 0) {
            bf.put(comment.getBytes(StandardCharsets.UTF_8));
        }
        return bf.array();
    }

    public short getVersion() {
        return version;
    }

    public void setVersion(short version) {
        this.version = version;
    }

    public short getVersionExtra() {
        return versionExtra;
    }

    public void setVersionExtra(short versionExtra) {
        this.versionExtra = versionExtra;
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

    public short getCommentLength() {
        return commentLength;
    }

    public void setCommentLength(short commentLength) {
        this.commentLength = commentLength;
    }

    public short getDiskNumStart() {
        return diskNumStart;
    }

    public void setDiskNumStart(short diskNumStart) {
        this.diskNumStart = diskNumStart;
    }

    public short getInternalFile() {
        return internalFile;
    }

    public void setInternalFile(short internalFile) {
        this.internalFile = internalFile;
    }

    public int getExternalFile() {
        return externalFile;
    }

    public void setExternalFile(int externalFile) {
        this.externalFile = externalFile;
    }

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
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

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }
}