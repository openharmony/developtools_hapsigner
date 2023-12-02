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


import com.ohos.hapsigntool.error.ZipException;
import com.ohos.hapsigntool.utils.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Zip {
    private List<ZipEntry> zipEntries;

    private long signingOffset;

    private byte[] signingBlock;

    private long CDOffset;

    private List<CentralDirectory> centralDirectories;

    private long EOCDOffset;

    private EndOfCentralDirectory endOfCentralDirectory;

    private String file;

    public Zip(File file) throws IOException {
        this.file = file.getPath();
        // 1. get eocd data
        endOfCentralDirectory = getZipEndOfCentralDirectory(file);
        // 2. use eocd's cd offset, get cd data
        centralDirectories = getZipCentralDirectory(file);
        // 3. use cd's entry offset and file size, get entry data
        zipEntries = getZipEntries(file);
        // 4. file data - eocd - cd - entry = sign block
        signingBlock = getSigningBlock(file);
    }

    private EndOfCentralDirectory getZipEndOfCentralDirectory(File file) throws IOException {
        EndOfCentralDirectory eocd;
        if (file.length() < EndOfCentralDirectory.eocdLength) {
            throw new ZipException("find zip eocd failed");
        }

        // try to read EOCD without comment
        int eocdMaxLength = EndOfCentralDirectory.eocdLength;
        EOCDOffset = file.length() - eocdMaxLength;
        byte[] bytes = FileUtils.readFileByOffsetAndLength(file, EOCDOffset, eocdMaxLength);
        eocd = EndOfCentralDirectory.initEOCDByBytes(bytes);
        if (eocd != null) {
            return eocd;
        }

        //try to search EOCD with comment
        int maxCommentLength = 65535;
        eocdMaxLength = EndOfCentralDirectory.eocdLength + maxCommentLength;
        EOCDOffset = file.length() - eocdMaxLength;
        bytes = FileUtils.readFileByOffsetAndLength(file, EOCDOffset, eocdMaxLength);
        for (int start = 0; start < eocdMaxLength; start++) {
            eocd = EndOfCentralDirectory.initEOCDByBytes(bytes);
            if (eocd != null) {
                EOCDOffset += start;
                return eocd;
            }
        }
        throw new ZipException("read zip failed: can not find eocd in file");
    }

    private List<CentralDirectory> getZipCentralDirectory(File file) throws IOException {
        List<CentralDirectory> cdList = new ArrayList<>(endOfCentralDirectory.getCDTotal());
        CDOffset = endOfCentralDirectory.getOffset();
        byte[] cdBytes = FileUtils.readFileByOffsetAndLength(file, CDOffset, endOfCentralDirectory.getCDSize());
        if (cdBytes.length < CentralDirectory.cdLength) {
            throw new ZipException("find zip cd failed");
        }
        int offset = 0;
        while (offset < cdBytes.length) {
            CentralDirectory cd = CentralDirectory.initCentralDirectory(cdBytes, offset);
            if (cd == null) {
                throw new ZipException("find zip cd failed");
            }
            cdList.add(cd);
            offset += CentralDirectory.cdLength + cd.getFileNameLength() + cd.getExtraLength() + cd.getCommentLength();
        }
        return cdList;
    }

    private byte[] getSigningBlock(File file) throws IOException {
        return FileUtils.readFileByOffsetAndLength(file, signingOffset, CDOffset - signingOffset);
    }

    private List<ZipEntry> getZipEntries(File file) throws IOException {
        List<ZipEntry> entryList = new ArrayList<>();
        for (CentralDirectory cd : centralDirectories) {
            long offset = cd.getOffset();
            long fileSize = cd.getCompressedSize();
            entryList.add(initZipEntry(file, offset, fileSize));
        }
        return entryList;
    }

    private ZipEntry initZipEntry(File file, long entryOffset, long fileSize) throws IOException {
        ZipEntry entry = new ZipEntry();
        long offset = entryOffset;
        byte[] headBytes = FileUtils.readFileByOffsetAndLength(file, offset, ZipEntryHeader.headerLength);
        ZipEntryHeader zipEntryHeader = ZipEntryHeader.initZipEntryHeader(headBytes);
        if (zipEntryHeader == null) {
            throw new ZipException("find zip entry head failed");
        }
        offset += ZipEntryHeader.headerLength;
        byte[] nameExtra = FileUtils.readFileByOffsetAndLength(file, offset, zipEntryHeader.getFileNameLength() + zipEntryHeader.getExtraLength());
        zipEntryHeader.setNameAndExtra(nameExtra);

        offset += zipEntryHeader.getFileNameLength() + zipEntryHeader.getExtraLength();
        entry.setFileOffset(offset);
        entry.setFileSize(fileSize);

        offset += fileSize;
        byte[] desBytes = FileUtils.readFileByOffsetAndLength(file, offset, DataDescriptor.desLength);
        DataDescriptor dataDescriptor = DataDescriptor.initDataDescriptor(desBytes);
        if (dataDescriptor == null) {
            throw new ZipException("find zip entry desc failed");
        }

        entry.setDataDescriptor(dataDescriptor);
        entry.setZipEntryHeader(zipEntryHeader);
        return entry;
    }

    public void toFile(String file) {
        for (ZipEntry zipEntry : zipEntries) {
            FileUtils.writeByteToOutFile(zipEntry.getZipEntryHeader().toBytes(), file);
            // TODO 需要根据源文件，按照offset写入压缩后数据
//            FileUtils.wri(zipEntry.getZipEntryData(), file);
            FileUtils.writeByteToOutFile(zipEntry.getDataDescriptor().toBytes(), file);
        }
        FileUtils.writeByteToOutFile(signingBlock, file);
        for (CentralDirectory cd : centralDirectories) {
            FileUtils.writeByteToOutFile(cd.toBytes(), file);
        }
        FileUtils.writeByteToOutFile(endOfCentralDirectory.toBytes(), file);
    }

    public void alignment() {
        // TODO 字节对齐逻辑
    }
    public List<ZipEntry> getZipEntries() {
        return zipEntries;
    }

    public void setZipEntries(List<ZipEntry> zipEntries) {
        this.zipEntries = zipEntries;
    }

    public long getSigningOffset() {
        return signingOffset;
    }

    public void setSigningOffset(long signingOffset) {
        this.signingOffset = signingOffset;
    }

    public byte[] getSigningBlock() {
        return signingBlock;
    }

    public void setSigningBlock(byte[] signingBlock) {
        this.signingBlock = signingBlock;
    }

    public long getCDOffset() {
        return CDOffset;
    }

    public void setCDOffset(long CDOffset) {
        this.CDOffset = CDOffset;
    }

    public List<CentralDirectory> getCentralDirectories() {
        return centralDirectories;
    }

    public void setCentralDirectories(List<CentralDirectory> centralDirectories) {
        this.centralDirectories = centralDirectories;
    }

    public long getEOCDOffset() {
        return EOCDOffset;
    }

    public void setEOCDOffset(long EOCDOffset) {
        this.EOCDOffset = EOCDOffset;
    }

    public EndOfCentralDirectory getEndOfCentralDirectory() {
        return endOfCentralDirectory;
    }

    public void setEndOfCentralDirectory(EndOfCentralDirectory endOfCentralDirectory) {
        this.endOfCentralDirectory = endOfCentralDirectory;
    }

    public String getFile() {
        return file;
    }

    public void setFile(String file) {
        this.file = file;
    }
}