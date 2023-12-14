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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * resolve zip EndOfCentralDirectory data
 *
 * @since 2023/12/04
 */
class EndOfCentralDirectory {
    /**
     * EndOfCentralDirectory invariable bytes length
     */
    public static final int EOCD_LENGTH = 22;

    /**
     * 4 bytes , central directory signature
     */
    public static final int SIGNATURE = 0x06054b50;

    /**
     * 2 bytes
     */
    private int diskNum;

    /**
     * 2 bytes
     */
    private int cDStartDiskNum;

    /**
     * 2 bytes
     */
    private int thisDiskCDNum;

    /**
     * 2 bytes
     */
    private int cDTotal;

    /**
     * 4 bytes
     */
    private long cDSize;

    /**
     * 4 bytes
     */
    private long offset;

    /**
     * 2 bytes
     */
    private int commentLength;

    /**
     * n bytes
     */
    private String comment;

    private int length;

    /**
     * init End Of Central Directory, default offset is 0
     *
     * @param bytes End Of Central Directory bytes
     * @return End Of Central Directory
     */
    public static EndOfCentralDirectory getEOCDByBytes(byte[] bytes) {
        return getEOCDByBytes(bytes, 0);
    }

    /**
     * init End Of Central Directory
     *
     * @param bytes End Of Central Directory bytes
     * @param offset offset
     * @return End Of Central Directory
     */
    public static EndOfCentralDirectory getEOCDByBytes(byte[] bytes, int offset) {
        EndOfCentralDirectory eocd = new EndOfCentralDirectory();
        int remainingDataLen = bytes.length - offset;
        ByteBuffer bf = ByteBuffer.wrap(bytes, offset, remainingDataLen);
        bf.order(ByteOrder.LITTLE_ENDIAN);
        if (bf.getInt() != SIGNATURE) {
            return null;
        }
        eocd.setDiskNum(UnsignedDecimalUtil.getUnsignedShort(bf));
        eocd.setcDStartDiskNum(UnsignedDecimalUtil.getUnsignedShort(bf));
        eocd.setThisDiskCDNum(UnsignedDecimalUtil.getUnsignedShort(bf));
        eocd.setcDTotal(UnsignedDecimalUtil.getUnsignedShort(bf));
        eocd.setcDSize(UnsignedDecimalUtil.getUnsignedInt(bf));
        eocd.setOffset(UnsignedDecimalUtil.getUnsignedInt(bf));
        eocd.setCommentLength(UnsignedDecimalUtil.getUnsignedShort(bf));
        if (eocd.getCommentLength() > 0) {
            byte[] readComment = new byte[eocd.getCommentLength()];
            bf.get(readComment);
            eocd.setComment(new String(readComment, StandardCharsets.UTF_8));
        }
        eocd.setLength(EOCD_LENGTH + eocd.getCommentLength());
        if (bf.remaining() != 0) {
            return null;
        }
        return eocd;
    }

    /**
     * change End Of Central Directory to bytes
     *
     * @return bytes
     */
    public byte[] toBytes() {
        ByteBuffer bf = ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN);
        bf.putInt(SIGNATURE);
        UnsignedDecimalUtil.setUnsignedShort(bf, diskNum);
        UnsignedDecimalUtil.setUnsignedShort(bf, cDStartDiskNum);
        UnsignedDecimalUtil.setUnsignedShort(bf, thisDiskCDNum);
        UnsignedDecimalUtil.setUnsignedShort(bf, cDTotal);
        UnsignedDecimalUtil.setUnsignedInt(bf, cDSize);
        UnsignedDecimalUtil.setUnsignedInt(bf, offset);
        UnsignedDecimalUtil.setUnsignedShort(bf, commentLength);
        if (commentLength > 0) {
            bf.put(comment.getBytes(StandardCharsets.UTF_8));
        }
        return bf.array();
    }

    public static int getEocdLength() {
        return EOCD_LENGTH;
    }

    public static int getSIGNATURE() {
        return SIGNATURE;
    }

    public int getDiskNum() {
        return diskNum;
    }

    public void setDiskNum(int diskNum) {
        this.diskNum = diskNum;
    }

    public int getcDStartDiskNum() {
        return cDStartDiskNum;
    }

    public void setcDStartDiskNum(int cDStartDiskNum) {
        this.cDStartDiskNum = cDStartDiskNum;
    }

    public int getThisDiskCDNum() {
        return thisDiskCDNum;
    }

    public void setThisDiskCDNum(int thisDiskCDNum) {
        this.thisDiskCDNum = thisDiskCDNum;
    }

    public int getcDTotal() {
        return cDTotal;
    }

    public void setcDTotal(int cDTotal) {
        this.cDTotal = cDTotal;
    }

    public long getcDSize() {
        return cDSize;
    }

    public void setcDSize(long cDSize) {
        this.cDSize = cDSize;
    }

    public long getOffset() {
        return offset;
    }

    public void setOffset(long offset) {
        this.offset = offset;
    }

    public int getCommentLength() {
        return commentLength;
    }

    public void setCommentLength(int commentLength) {
        this.commentLength = commentLength;
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