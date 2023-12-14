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
        try (FileInputStream input = new FileInputStream(file)) {
            long offset = entryOffset;
            // read entry header by file and offset.
            byte[] headBytes = FileUtils.readInputByOffsetAndLength(input, entryOffset, ZipEntryHeader.HEADER_LENGTH);
            ZipEntryHeader entryHeader = ZipEntryHeader.initZipEntryHeader(headBytes);
            offset += ZipEntryHeader.HEADER_LENGTH;

            // read entry file name and extra by offset.
            int nameAndExtraLength = entryHeader.getFileNameLength() + entryHeader.getExtraLength();
            byte[] nameAndExtra = FileUtils.readInputByLength(input, nameAndExtraLength);
            entryHeader.setNameAndExtra(nameAndExtra);
            offset += nameAndExtraLength;

            // skip file data , save file offset and size.
            ZipEntryData entry = new ZipEntryData();
            entry.setFileOffset(offset);
            entry.setFileSize(compress);
            input.skip(compress);

            long entryLength = entryHeader.getLength() + compress;
            if (hasDesc) {
                // if entry has data descriptor, read entry data descriptor.
                byte[] desBytes = FileUtils.readInputByLength(input, DataDescriptor.DES_LENGTH);
                DataDescriptor dataDesc = DataDescriptor.initDataDescriptor(desBytes);
                entryLength += DataDescriptor.DES_LENGTH;
                entry.setDataDescriptor(dataDesc);
            }
            entry.setZipEntryHeader(entryHeader);
            entry.setLength(entryLength);
            return entry;
        }
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