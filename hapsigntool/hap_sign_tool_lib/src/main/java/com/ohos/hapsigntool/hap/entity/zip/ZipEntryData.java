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
import com.ohos.hapsigntool.utils.FileUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * resolve zip ZipEntry data
 *
 * @since 2023/12/04
 */
class ZipEntryData {
    private ZipEntryHeader zipEntryHeader;

    private long fileOffset;

    private long fileSize;

    private DataDescriptor dataDescriptor;

    private long length;

    public ZipEntryHeader getZipEntryHeader() {
        return zipEntryHeader;
    }

    /**
     * init zip entry by file
     *
     * @param file zip file
     * @param entryOffset entry start offset
     * @param compress compress file size
     * @param hasDesc has data descriptor
     * @return zip entry
     * @throws IOException read zip exception
     */
    public static ZipEntryData initZipEntry(File file, long entryOffset, long compress, boolean hasDesc)
            throws IOException {
        try (FileInputStream fs = new FileInputStream(file)) {
            long offset = entryOffset;
            fs.skip(offset);
            byte[] headBytes = FileUtils.readFileByOffsetAndLength(fs, 0, ZipEntryHeader.HEADER_LENGTH);
            ZipEntryHeader entryHeader = ZipEntryHeader.initZipEntryHeader(headBytes);
            if (entryHeader == null) {
                throw new ZipException("find zip entry head failed");
            }
            offset += ZipEntryHeader.HEADER_LENGTH;
            byte[] nameAndExtra = FileUtils.readFileByOffsetAndLength(fs, 0,
                    entryHeader.getFileNameLength() + entryHeader.getExtraLength());
            entryHeader.setNameAndExtra(nameAndExtra);

            offset += entryHeader.getFileNameLength() + entryHeader.getExtraLength();

            ZipEntryData entry = new ZipEntryData();
            entry.setFileOffset(offset);
            entry.setFileSize(compress);
            fs.skip(compress);

            offset += compress;
            long entryLength = entryHeader.getLength() + compress;

            if (hasDesc) {
                byte[] desBytes = FileUtils.readFileByOffsetAndLength(fs, 0, DataDescriptor.DES_LENGTH);
                DataDescriptor dataDesc = DataDescriptor.initDataDescriptor(desBytes);
                if (dataDesc == null) {
                    throw new ZipException("find zip entry desc failed");
                }
                entryLength += DataDescriptor.DES_LENGTH;
                entry.setDataDescriptor(dataDesc);
            }
            entry.setZipEntryHeader(entryHeader);
            entry.setLength(entryLength);
            return entry;
        }
    }

    /**
     * alignment one entry
     *
     * @param alignNum  need align bytes length
     * @return add bytes length
     * @throws ZipException alignment exception
     */
    public short alignment(short alignNum) throws ZipException {
        long add = alignNum - length % alignNum;
        if (add == alignNum) {
            return 0;
        }
        if (add > Short.MAX_VALUE) {
            throw new ZipException("can not align " + zipEntryHeader.getFileName());
        }
        int newExtraLength = zipEntryHeader.getExtraLength() + (short) add;
        if (newExtraLength > Short.MAX_VALUE) {
            throw new ZipException("can not align " + zipEntryHeader.getFileName());
        }
        short extraLength = (short) newExtraLength;
        zipEntryHeader.setExtraLength(extraLength);
        byte[] extra = new byte[extraLength];
        zipEntryHeader.setExtraData(extra);
        int newLength = ZipEntryHeader.HEADER_LENGTH
                + zipEntryHeader.getFileNameLength() + zipEntryHeader.getExtraData().length;
        if (zipEntryHeader.getLength() + add != newLength) {
            throw new ZipException("can not align " + zipEntryHeader.getFileName());
        }
        zipEntryHeader.setLength(newLength);
        this.length += add;
        return (short) add;
    }

    public void setZipEntryHeader(ZipEntryHeader zipEntryHeader) {
        this.zipEntryHeader = zipEntryHeader;
    }

    public DataDescriptor getDataDescriptor() {
        return dataDescriptor;
    }

    public void setDataDescriptor(DataDescriptor dataDescriptor) {
        this.dataDescriptor = dataDescriptor;
    }

    public long getFileOffset() {
        return fileOffset;
    }

    public void setFileOffset(long fileOffset) {
        this.fileOffset = fileOffset;
    }

    public long getFileSize() {
        return fileSize;
    }

    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }

    public long getLength() {
        return length;
    }

    public void setLength(long length) {
        this.length = length;
    }
}