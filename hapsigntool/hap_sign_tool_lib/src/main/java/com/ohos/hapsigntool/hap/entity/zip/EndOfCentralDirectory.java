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
    private short diskNum;

    /**
     * 2 bytes
     */
    private short cDStartDiskNum;

    /**
     * 2 bytes
     */
    private short thisDiskCDNum;

    /**
     * 2 bytes
     */
    private short cDTotal;

    /**
     * 4 bytes
     */
    private int cDSize;

    /**
     * 4 bytes
     */
    private int offset;

    /**
     * 2 bytes
     */
    private short commentLength;

    /**
     * n bytes
     */
    private String comment;

    private int length;

    /**
     * init End Of Central Directory
     *
     * @param bytes End Of Central Directory bytes
     * @return End Of Central Directory
     */
    public static EndOfCentralDirectory initEOCDByBytes(byte[] bytes) {
        EndOfCentralDirectory eocd = new EndOfCentralDirectory();
        ByteBuffer bf = ByteBuffer.allocate(bytes.length);
        bf.put(bytes);
        bf.order(ByteOrder.LITTLE_ENDIAN);
        bf.flip();
        if (bf.getInt() != SIGNATURE) {
            return null;
        }
        eocd.setDiskNum(bf.getShort());
        eocd.setCDStartDiskNum(bf.getShort());
        eocd.setThisDiskCDNum(bf.getShort());
        eocd.setCDTotal(bf.getShort());
        eocd.setCDSize(bf.getInt());
        eocd.setOffset(bf.getInt());
        eocd.setCommentLength(bf.getShort());
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
        bf.putShort(diskNum);
        bf.putShort(cDStartDiskNum);
        bf.putShort(thisDiskCDNum);
        bf.putShort(cDTotal);
        bf.putInt(cDSize);
        bf.putInt(offset);
        bf.putShort(commentLength);
        if (commentLength > 0) {
            bf.put(comment.getBytes(StandardCharsets.UTF_8));
        }
        return bf.array();
    }

    public short getDiskNum() {
        return diskNum;
    }

    public void setDiskNum(short diskNum) {
        this.diskNum = diskNum;
    }

    public short getCDStartDiskNum() {
        return cDStartDiskNum;
    }

    public void setCDStartDiskNum(short cDStartDiskNum) {
        this.cDStartDiskNum = cDStartDiskNum;
    }

    public short getThisDiskCDNum() {
        return thisDiskCDNum;
    }

    public void setThisDiskCDNum(short thisDiskCDNum) {
        this.thisDiskCDNum = thisDiskCDNum;
    }

    public short getCDTotal() {
        return cDTotal;
    }

    public void setCDTotal(short cDTotal) {
        this.cDTotal = cDTotal;
    }

    public int getCDSize() {
        return cDSize;
    }

    public void setCDSize(int cDSize) {
        this.cDSize = cDSize;
    }

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }

    public short getCommentLength() {
        return commentLength;
    }

    public void setCommentLength(short commentLength) {
        this.commentLength = commentLength;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }
    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }
}