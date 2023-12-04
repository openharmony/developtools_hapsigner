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

    public static ZipEntryData initZipEntry(File file, long entryOffset, long fileSize, boolean descFlag) throws IOException {
        ZipEntryData entry = new ZipEntryData();
        long offset = entryOffset;
        byte[] headBytes = FileUtils.readFileByOffsetAndLength(file, offset, ZipEntryHeader.headerLength);
        ZipEntryHeader zipEntryHeader = ZipEntryHeader.initZipEntryHeader(headBytes);
        if (zipEntryHeader == null) {
            throw new ZipException("find zip entry head failed");
        }
        offset += ZipEntryHeader.headerLength;
        byte[] nameAndExtra = FileUtils.readFileByOffsetAndLength(file, offset,
                zipEntryHeader.getFileNameLength() + zipEntryHeader.getExtraLength());
        zipEntryHeader.setNameAndExtra(nameAndExtra);

        offset += zipEntryHeader.getFileNameLength() + zipEntryHeader.getExtraLength();
        entry.setFileOffset(offset);
        entry.setFileSize(fileSize);

        offset += fileSize;
        long length = zipEntryHeader.getLength() + fileSize;

        if (descFlag) {
            byte[] desBytes = FileUtils.readFileByOffsetAndLength(file, offset, DataDescriptor.desLength);
            DataDescriptor dataDescriptor = DataDescriptor.initDataDescriptor(desBytes);
            if (dataDescriptor == null) {
                throw new ZipException("find zip entry desc failed");
            }
            length += DataDescriptor.desLength;
            entry.setDataDescriptor(dataDescriptor);
        }

        entry.setZipEntryHeader(zipEntryHeader);
        entry.setLength(length);
        return entry;
    }

    public short alignment(short alignNum) throws ZipException {
        long add = alignNum - length % alignNum;
        if (add > Short.MAX_VALUE) {
            throw new ZipException("can not align " + zipEntryHeader.getFileName());
        }
        int newExtraLength = zipEntryHeader.getExtraLength() + (short) add;
        if (newExtraLength > Short.MAX_VALUE) {
            throw new ZipException("can not align " + zipEntryHeader.getFileName());
        }
        short length = (short) newExtraLength;
        zipEntryHeader.setExtraLength(length);
        byte[] extra = new byte[length];
        zipEntryHeader.setExtraData(extra);
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