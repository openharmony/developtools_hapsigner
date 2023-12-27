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

    private CentralDirectory centralDirectory;

    /**
     * alignment one entry
     *
     * @param alignNum  need align bytes length
     * @return add bytes length
     * @throws ZipException alignment exception
     */
    public int alignment(int alignNum) throws ZipException {
        int remainder = (int) (zipEntryData.getZipEntryHeader().getLength() + centralDirectory.getOffset()) % alignNum;
        if (remainder == 0) {
            return 0;
        }
        int add = alignNum - remainder;
        int newExtraLength = zipEntryData.getZipEntryHeader().getExtraLength() + add;
        if (newExtraLength > UnsignedDecimalUtil.MAX_UNSIGNED_SHORT_VALUE) {
            throw new ZipException("can not align " + zipEntryData.getZipEntryHeader().getFileName());
        }
        // add entry extra
        zipEntryData.getZipEntryHeader().setExtraLength(newExtraLength);
        byte[] oldExtraData = zipEntryData.getZipEntryHeader().getExtraData();
        byte[] newExtra = getAlignmentNewExtra(newExtraLength, oldExtraData);
        zipEntryData.getZipEntryHeader().setExtraData(newExtra);
        int newLength = ZipEntryHeader.HEADER_LENGTH + zipEntryData.getZipEntryHeader().getFileNameLength()
                + newExtraLength;
        if (zipEntryData.getZipEntryHeader().getLength() + add != newLength) {
            throw new ZipException("can not align " + zipEntryData.getZipEntryHeader().getFileName());
        }
        zipEntryData.getZipEntryHeader().setLength(newLength);
        zipEntryData.setLength(zipEntryData.getLength() + add);

        // add cd extra
        byte[] oldCDExtra = centralDirectory.getExtraData();
        byte[] newCDExtra = getAlignmentNewExtra(newExtraLength, oldCDExtra);
        centralDirectory.setExtraData(newCDExtra);
        centralDirectory.setLength(centralDirectory.getLength() - centralDirectory.getExtraLength() + newCDExtra.length);
        centralDirectory.setExtraLength(newCDExtra.length);
        return add;
    }

    private byte[] getAlignmentNewExtra(int newLength, byte[] old) {
        if (old == null) {
            return new byte[newLength];
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
        return centralDirectory;
    }

    public void setCentralDirectory(CentralDirectory centralDirectory) {
        this.centralDirectory = centralDirectory;
    }
}