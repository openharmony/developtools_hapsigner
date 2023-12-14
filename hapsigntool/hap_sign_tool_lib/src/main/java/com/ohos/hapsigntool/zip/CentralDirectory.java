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

package com.ohos.hapsigntool.zip;

import com.ohos.hapsigntool.error.ZipException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * resolve zip CentralDirectory data
 *
 * @since 2023/12/02
 */
public class CentralDirectory {
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
    private long compressedSize;

    /**
     * 4 bytes
     */
    private long unCompressedSize;

    /**
     * 2 bytes
     */
    private int fileNameLength;

    /**
     * 2 bytes
     */
    private int extraLength;

    /**
     * 2 bytes
     */
    private int commentLength;

    /**
     * 2 bytes
     */
    private int diskNumStart;

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
    private long offset;

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
     * @param bf ByteBuffer
     * @return CentralDirectory
     * @throws ZipException read Central Directory exception
     */
    public static CentralDirectory getCentralDirectory(ByteBuffer bf) throws ZipException {
        CentralDirectory cd = new CentralDirectory();
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
        cd.setCompressedSize(UnsignedDecimalUtil.getUnsignedInt(bf));
        cd.setUnCompressedSize(UnsignedDecimalUtil.getUnsignedInt(bf));
        cd.setFileNameLength(UnsignedDecimalUtil.getUnsignedShort(bf));
        cd.setExtraLength(UnsignedDecimalUtil.getUnsignedShort(bf));
        cd.setCommentLength(UnsignedDecimalUtil.getUnsignedShort(bf));
        cd.setDiskNumStart(UnsignedDecimalUtil.getUnsignedShort(bf));
        cd.setInternalFile(bf.getShort());
        cd.setExternalFile(bf.getInt());
        cd.setOffset(UnsignedDecimalUtil.getUnsignedInt(bf));
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
        cd.setLength(CD_LENGTH + cd.getFileNameLength() + cd.getExtraLength() + cd.getCommentLength());
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
        UnsignedDecimalUtil.setUnsignedShort(bf, version);
        UnsignedDecimalUtil.setUnsignedShort(bf, versionExtra);
        UnsignedDecimalUtil.setUnsignedShort(bf, flag);
        UnsignedDecimalUtil.setUnsignedShort(bf, method);
        UnsignedDecimalUtil.setUnsignedShort(bf, lastTime);
        UnsignedDecimalUtil.setUnsignedShort(bf, lastDate);
        UnsignedDecimalUtil.setUnsignedInt(bf, crc32);
        UnsignedDecimalUtil.setUnsignedInt(bf, compressedSize);
        UnsignedDecimalUtil.setUnsignedInt(bf, unCompressedSize);
        UnsignedDecimalUtil.setUnsignedShort(bf, fileNameLength);
        UnsignedDecimalUtil.setUnsignedShort(bf, extraLength);
        UnsignedDecimalUtil.setUnsignedShort(bf, commentLength);
        UnsignedDecimalUtil.setUnsignedShort(bf, diskNumStart);
        UnsignedDecimalUtil.setUnsignedShort(bf, internalFile);
        UnsignedDecimalUtil.setUnsignedInt(bf, externalFile);
        UnsignedDecimalUtil.setUnsignedInt(bf, offset);
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

    public static int getCdLength() {
        return CD_LENGTH;
    }

    public static int getSIGNATURE() {
        return SIGNATURE;
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

    public long getCompressedSize() {
        return compressedSize;
    }

    public void setCompressedSize(long compressedSize) {
        this.compressedSize = compressedSize;
    }

    public long getUnCompressedSize() {
        return unCompressedSize;
    }

    public void setUnCompressedSize(long unCompressedSize) {
        this.unCompressedSize = unCompressedSize;
    }

    public int getFileNameLength() {
        return fileNameLength;
    }

    public void setFileNameLength(int fileNameLength) {
        this.fileNameLength = fileNameLength;
    }

    public int getExtraLength() {
        return extraLength;
    }

    public void setExtraLength(int extraLength) {
        this.extraLength = extraLength;
    }

    public int getCommentLength() {
        return commentLength;
    }

    public void setCommentLength(int commentLength) {
        this.commentLength = commentLength;
    }

    public int getDiskNumStart() {
        return diskNumStart;
    }

    public void setDiskNumStart(int diskNumStart) {
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

    public long getOffset() {
        return offset;
    }

    public void setOffset(long offset) {
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