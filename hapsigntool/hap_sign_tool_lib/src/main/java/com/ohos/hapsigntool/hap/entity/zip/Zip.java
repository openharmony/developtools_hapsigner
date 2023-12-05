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
import java.util.ArrayList;
import java.util.List;

/**
 * resolve zip data
 *
 * @since 2023/12/02
 */
public class Zip {
    private List<ZipEntry> zipEntries;

    private long signingOffset;

    private byte[] signingBlock;

    private long cDOffset;

    private long eOCDOffset;

    private EndOfCentralDirectory endOfCentralDirectory;

    private String file;

    private final List<String> suffix4K = new ArrayList<String>() {{
        add(".so");
        add(".abc");
    }};

    private final short unCompressMethod = 0;

    /**
     * create Zip by file
     *
     * @param file file
     * @throws IOException read file exception
     */
    public Zip(File file) throws IOException {
        this.file = file.getPath();
        if (!file.exists()) {
            throw new ZipException("read zip file failed");
        }
        // 1. get eocd data
        endOfCentralDirectory = getZipEndOfCentralDirectory(file);
        // 2. use eocd's cd offset, get cd data
        getZipCentralDirectory(file);
        // 3. use cd's entry offset and file size, get entry data
        getZipEntries(file);
        // 4. file all data - eocd - cd - entry = sign block
        signingBlock = getSigningBlock(file);
    }

    private EndOfCentralDirectory getZipEndOfCentralDirectory(File file) throws IOException {
        if (file.length() < EndOfCentralDirectory.EOCD_LENGTH) {
            throw new ZipException("find zip eocd failed");
        }

        // try to read EOCD without comment
        int eocdMaxLength = EndOfCentralDirectory.EOCD_LENGTH;
        eOCDOffset = file.length() - eocdMaxLength;
        byte[] bytes = FileUtils.readFileByOffsetAndLength(file, eOCDOffset, eocdMaxLength);
        EndOfCentralDirectory eocd = EndOfCentralDirectory.initEOCDByBytes(bytes);
        if (eocd != null) {
            return eocd;
        }

        // try to search EOCD with comment
        int maxCommentLength = 65535;
        eocdMaxLength = EndOfCentralDirectory.EOCD_LENGTH + maxCommentLength;
        eOCDOffset = file.length() - eocdMaxLength;
        bytes = FileUtils.readFileByOffsetAndLength(file, eOCDOffset, eocdMaxLength);
        for (int start = 0; start < eocdMaxLength; start++) {
            eocd = EndOfCentralDirectory.initEOCDByBytes(bytes);
            if (eocd != null) {
                eOCDOffset += start;
                return eocd;
            }
        }
        throw new ZipException("read zip failed: can not find eocd in file");
    }

    private void getZipCentralDirectory(File file) throws IOException {
        zipEntries = new ArrayList<>(endOfCentralDirectory.getCDTotal());
        cDOffset = endOfCentralDirectory.getOffset();
        // read full central directory bytes
        byte[] cdBytes = FileUtils.readFileByOffsetAndLength(file, cDOffset, endOfCentralDirectory.getCDSize());
        if (cdBytes.length < CentralDirectory.CD_LENGTH) {
            throw new ZipException("find zip cd failed");
        }
        int offset = 0;
        // one by one format central directory
        while (offset < cdBytes.length) {
            CentralDirectory cd = CentralDirectory.initCentralDirectory(cdBytes, offset);
            ZipEntry entry = new ZipEntry();
            entry.setCentralDirectory(cd);
            zipEntries.add(entry);
            offset += cd.getLength();
        }
    }

    private byte[] getSigningBlock(File file) throws IOException {
        return FileUtils.readFileByOffsetAndLength(file, signingOffset, cDOffset - signingOffset);
    }

    private void getZipEntries(File file) throws IOException {
        // use central directory data, find entry data
        for (ZipEntry entry : zipEntries) {
            CentralDirectory cd = entry.getCentralDirectory();
            long offset = cd.getOffset();
            long fileSize = cd.getCompressedSize();
            short flag = cd.getFlag();
            short i = 0x08;
            // set desc null flag
            boolean hasDesc = (flag & i) != 0;
            entry.setZipEntryData(ZipEntryData.initZipEntry(file, offset, fileSize, hasDesc));
        }
        ZipEntry endEntry = zipEntries.get(zipEntries.size() - 1);
        CentralDirectory endCD = endEntry.getCentralDirectory();
        ZipEntryData endEntryData = endEntry.getZipEntryData();
        signingOffset = endCD.getOffset() + endEntryData.getLength();
    }

    /**
     * output zip to zip file
     *
     * @param file file path
     * @throws IOException write exception
     */
    public void toFile(String file) throws IOException {
        File f = new File(file);
        if (!f.exists()) {
            f.createNewFile();
        }
        FileUtils.write(new byte[]{}, f);
        for (ZipEntry entry : zipEntries) {
            ZipEntryData zipEntryData = entry.getZipEntryData();
            FileUtils.writeByteToOutFile(zipEntryData.getZipEntryHeader().toBytes(), file);
            boolean isSuccess = FileUtils.appendWriteFileByOffsetToFile(this.file, file,
                    zipEntryData.getFileOffset(), zipEntryData.getFileSize());
            if (!isSuccess) {
                throw new ZipException("write zip data failed");
            }
            if (zipEntryData.getDataDescriptor() != null) {
                FileUtils.writeByteToOutFile(zipEntryData.getDataDescriptor().toBytes(), file);
            }
        }
        FileUtils.writeByteToOutFile(signingBlock, file);
        for (ZipEntry entry : zipEntries) {
            CentralDirectory cd = entry.getCentralDirectory();
            FileUtils.writeByteToOutFile(cd.toBytes(), file);
        }
        FileUtils.writeByteToOutFile(endOfCentralDirectory.toBytes(), file);
    }

    /**
     * alignment uncompress entry
     *
     * @throws ZipException alignment exception
     */
    public void alignment() throws ZipException {
        for (ZipEntry entry : zipEntries) {
            ZipEntryData zipEntryData = entry.getZipEntryData();
            short method = zipEntryData.getZipEntryHeader().getMethod();
            if (method != unCompressMethod) {
                // only align uncompressed entry.
                continue;
            }
            // normal file align 4 byte.
            short alignBytes = 4;
            if (is4kAlignSuffix(zipEntryData.getZipEntryHeader().getFileName())) {
                // .abc and .so file align 4096 byte.
                alignBytes = 4096;
            }
            short alignment = zipEntryData.alignment(alignBytes);
            if (alignment > 0) {
                int offset = entry.getCentralDirectory().getOffset() + alignment;
                entry.getCentralDirectory().setOffset(offset);
                endOfCentralDirectory.setOffset(endOfCentralDirectory.getOffset() + alignment);
                eOCDOffset += alignment;
                cDOffset += alignment;
            }
        }
    }

    /**
     * sort uncompress entry in the front.
     */
    public void sort() {
        int unCompressOffset = 0;
        int compressOffset = zipEntries.size() - 1;
        int pointer = 0;
        // sort uncompress file (so, abc) - other uncompress file - compress file
        while (pointer <= compressOffset) {
            ZipEntry entry = zipEntries.get(pointer);
            if (is4kAlignSuffix(entry.getZipEntryData().getZipEntryHeader().getFileName())
                    && entry.getZipEntryData().getZipEntryHeader().getMethod() == unCompressMethod) {
                ZipEntry temp = zipEntries.get(unCompressOffset);
                zipEntries.set(unCompressOffset, zipEntries.get(pointer));
                zipEntries.set(pointer, temp);
                unCompressOffset++;
                pointer++;
                continue;
            }
            if (entry.getZipEntryData().getZipEntryHeader().getMethod() != unCompressMethod) {
                ZipEntry temp = zipEntries.get(compressOffset);
                zipEntries.set(compressOffset, zipEntries.get(pointer));
                zipEntries.set(pointer, temp);
                compressOffset--;
                continue;
            }
            pointer++;
        }
        // reset offset
        int offset = 0;
        for (ZipEntry entry : zipEntries) {
            entry.getCentralDirectory().setOffset(offset);
            offset += entry.getZipEntryData().getLength();
        }
    }

    private boolean is4kAlignSuffix(String name) {
        for (String suffix : suffix4K) {
            if (name.endsWith(suffix)) {
                return true;
            }
        }
        return false;
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
        return cDOffset;
    }

    public void setCDOffset(long cDOffset) {
        this.cDOffset = cDOffset;
    }

    public long getEOCDOffset() {
        return eOCDOffset;
    }

    public void setEOCDOffset(long eOCDOffset) {
        this.eOCDOffset = eOCDOffset;
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

    public List<String> getSuffix4K() {
        return suffix4K;
    }

    public short getUnCompressMethod() {
        return unCompressMethod;
    }
}