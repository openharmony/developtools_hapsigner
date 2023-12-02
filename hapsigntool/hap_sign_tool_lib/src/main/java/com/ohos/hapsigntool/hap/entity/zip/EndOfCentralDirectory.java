/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

class EndOfCentralDirectory {
    public static final int eocdLength = 22;

    /**
     * 4 bytes
     */
    public static final int signature = 0x06054b50;

    /**
     * 2 bytes
     */
    private short diskNum;


    /**
     * 2 bytes
     */
    private short CDStartDiskNum;

    /**
     * 2 bytes
     */
    private short thisDiskCDNum;

    /**
     * 2 bytes
     */
    private short CDTotal;

    /**
     * 4 bytes
     */
    private int CDSize;

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

    public static EndOfCentralDirectory initEOCDByBytes(byte[] bytes) {
        EndOfCentralDirectory eocd = new EndOfCentralDirectory();
        ByteBuffer bf = ByteBuffer.allocate(bytes.length);
        bf.put(bytes);
        bf.order(ByteOrder.LITTLE_ENDIAN);
        bf.flip();
        if (bf.getInt() != signature) {
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
            byte[] comment = new byte[eocd.getCommentLength()];
            bf.get(comment);
            eocd.setComment(new String(comment, StandardCharsets.UTF_8));
        }
        if (bf.remaining() != 0) {
            return null;
        }
        return eocd;
    }

    public byte[] toBytes() {
        ByteBuffer bf = ByteBuffer.allocate(eocdLength + commentLength).order(ByteOrder.LITTLE_ENDIAN);
        bf.putInt(signature);
        bf.putShort(diskNum);
        bf.putShort(CDStartDiskNum);
        bf.putShort(thisDiskCDNum);
        bf.putShort(CDTotal);
        bf.putInt(CDSize);
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
        return CDStartDiskNum;
    }

    public void setCDStartDiskNum(short CDStartDiskNum) {
        this.CDStartDiskNum = CDStartDiskNum;
    }

    public short getThisDiskCDNum() {
        return thisDiskCDNum;
    }

    public void setThisDiskCDNum(short thisDiskCDNum) {
        this.thisDiskCDNum = thisDiskCDNum;
    }

    public short getCDTotal() {
        return CDTotal;
    }

    public void setCDTotal(short CDTotal) {
        this.CDTotal = CDTotal;
    }

    public int getCDSize() {
        return CDSize;
    }

    public void setCDSize(int CDSize) {
        this.CDSize = CDSize;
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

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }
}