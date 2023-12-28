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

import java.util.Arrays;

/**
 * ZipEntry and CentralDirectory data
 *
 * @since 2023/12/02
 */
public class ZipEntry {
    private ZipEntryData zipEntryData;

    private CentralDirectory fileEntryIncentralDirectory;

    /**
     * alignment one entry
     *
     * @param alignNum  need align bytes length
     * @return add bytes length
     * @throws ZipException alignment exception
     */
    public int alignment(int alignNum) throws ZipException {
        // if cd extra len bigger than entry extra len, make cd and entry extra length equals
        int padding = calZeroPaddingLengthForEntryExtra();
        int remainder = (int) ((zipEntryData.getZipEntryHeader().getLength()
                + fileEntryIncentralDirectory.getOffset()) % alignNum);

        if (remainder == 0) {
            return padding;
        }
        int add = alignNum - remainder;
        int newExtraLength = zipEntryData.getZipEntryHeader().getExtraLength() + add;
        if (newExtraLength > UnsignedDecimalUtil.MAX_UNSIGNED_SHORT_VALUE) {
            throw new ZipException("can not align " + zipEntryData.getZipEntryHeader().getFileName());
        }
        setEntryHeaderNewExtraLength(newExtraLength);
        setCenterDirectoryNewExtraLength(newExtraLength);

        return add;
    }

    private int calZeroPaddingLengthForEntryExtra() throws ZipException {
        int entryExtraLen = zipEntryData.getZipEntryHeader().getExtraLength();
        int cdExtraLen = fileEntryIncentralDirectory.getExtraLength();
        if (cdExtraLen > entryExtraLen) {
            setEntryHeaderNewExtraLength(cdExtraLen);
            return cdExtraLen - entryExtraLen;
        }
        if (cdExtraLen < entryExtraLen) {
            setCenterDirectoryNewExtraLength(entryExtraLen);
            return entryExtraLen - cdExtraLen;
        }
        return 0;
    }

    private void setCenterDirectoryNewExtraLength(int newLength) throws ZipException {
        byte[] newCDExtra = getAlignmentNewExtra(newLength, fileEntryIncentralDirectory.getExtraData());
        fileEntryIncentralDirectory.setExtraData(newCDExtra);
        fileEntryIncentralDirectory.setExtraLength(newLength);
        fileEntryIncentralDirectory.setLength(CentralDirectory.CD_LENGTH
                + fileEntryIncentralDirectory.getFileNameLength()
                + fileEntryIncentralDirectory.getExtraLength() + fileEntryIncentralDirectory.getCommentLength());
    }

    private void setEntryHeaderNewExtraLength(int newLength) throws ZipException {
        ZipEntryHeader zipEntryHeader = zipEntryData.getZipEntryHeader();
        byte[] newExtra = getAlignmentNewExtra(newLength, zipEntryHeader.getExtraData());
        zipEntryHeader.setExtraData(newExtra);
        zipEntryHeader.setExtraLength(newLength);
        zipEntryHeader.setLength(ZipEntryHeader.HEADER_LENGTH + zipEntryHeader.getExtraLength()
                + zipEntryHeader.getFileNameLength());
        zipEntryData.setLength(zipEntryHeader.getLength() + zipEntryData.getFileSize()
                + (zipEntryData.getDataDescriptor() == null ? 0 : DataDescriptor.DES_LENGTH));
    }

    private byte[] getAlignmentNewExtra(int newLength, byte[] old) throws ZipException {
        if (old == null) {
            return new byte[newLength];
        }
        if (newLength < old.length) {
            throw new ZipException("can not align " + zipEntryData.getZipEntryHeader().getFileName());
        }
        return Arrays.copyOf(old, newLength);
    }

    public ZipEntryData getZipEntryData() {
        return zipEntryData;
    }

    public void setZipEntryData(ZipEntryData zipEntryData) {
        this.zipEntryData = zipEntryData;
    }

    public CentralDirectory getCentralDirectory() {
        return fileEntryIncentralDirectory;
    }

    public void setCentralDirectory(CentralDirectory centralDirectory) {
        this.fileEntryIncentralDirectory = centralDirectory;
    }
}