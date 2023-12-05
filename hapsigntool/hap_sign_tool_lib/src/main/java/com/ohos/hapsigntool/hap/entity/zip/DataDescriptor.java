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

/**
 * resolve zip DataDescriptor data
 *
 * @since 2023/12/02
 */
public class DataDescriptor {
    /**
     * DataDescriptor invariable bytes length
     */
    public static final int DES_LENGTH = 16;

    /**
     * 4 bytes , DataDescriptor signature
     */
    public static final int SIGNATURE = 0x08074b50;

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
     * init Central Directory
     *
     * @param bytes DataDescriptor bytes
     * @return DataDescriptor
     * @throws ZipException read data descriptor exception
     */
    public static DataDescriptor initDataDescriptor(byte[] bytes) throws ZipException {
        if (bytes.length != DES_LENGTH) {
            throw new ZipException("read Data Descriptor failed");
        }
        ByteBuffer bf = ByteBuffer.allocate(bytes.length);
        bf.put(bytes);
        bf.order(ByteOrder.LITTLE_ENDIAN);
        bf.flip();
        DataDescriptor data = new DataDescriptor();
        if (bf.getInt() != SIGNATURE) {
            throw new ZipException("read Data Descriptor failed");
        }
        data.setCrc32(bf.getInt());
        data.setCompressedSize(bf.getInt());
        data.setUnCompressedSize(bf.getInt());
        return data;
    }

    /**
     * change DataDescriptor to bytes
     *
     * @return bytes
     */
    public byte[] toBytes() {
        ByteBuffer bf = ByteBuffer.allocate(DES_LENGTH).order(ByteOrder.LITTLE_ENDIAN);
        bf.putInt(SIGNATURE);
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
