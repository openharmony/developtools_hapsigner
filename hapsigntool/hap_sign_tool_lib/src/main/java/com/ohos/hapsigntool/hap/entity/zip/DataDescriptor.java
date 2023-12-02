package com.ohos.hapsigntool.hap.entity.zip;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class DataDescriptor {
    public static final int desLength = 12;

    /**
     * 4 bytes
     */
    int crc32;

    /**
     * 4 bytes
     */
    int compressedSize;

    /**
     * 4 bytes
     */
    int unCompressedSize;

    public static DataDescriptor initDataDescriptor(byte[] bytes) {
        if (bytes.length != 12) {
            return null;
        }
        ByteBuffer bf = ByteBuffer.allocate(bytes.length);
        bf.put(bytes);
        bf.order(ByteOrder.LITTLE_ENDIAN);
        bf.flip();
        DataDescriptor data = new DataDescriptor();
        data.setCrc32(bf.getInt());
        data.setCompressedSize(bf.getInt());
        data.setUnCompressedSize(bf.getInt());
        return data;
    }

    public byte[] toBytes() {
        ByteBuffer bf = ByteBuffer.allocate(desLength).order(ByteOrder.LITTLE_ENDIAN);
        bf.putInt(crc32);
        bf.putInt(compressedSize);
        bf.putInt(unCompressedSize);
        return bf.array();
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
}
