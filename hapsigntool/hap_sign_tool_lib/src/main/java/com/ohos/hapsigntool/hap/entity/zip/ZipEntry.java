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

class ZipEntry {
    private ZipEntryHeader zipEntryHeader;

    private long fileOffset;

    private long fileSize;

    private DataDescriptor dataDescriptor;

    public ZipEntryHeader getZipEntryHeader() {
        return zipEntryHeader;
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
}