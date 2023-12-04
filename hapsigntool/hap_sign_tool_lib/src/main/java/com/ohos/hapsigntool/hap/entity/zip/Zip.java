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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
    private static final Logger LOGGER = LogManager.getLogger(Zip.class);

    private List<ZipEntry> zipEntries;

    private long signingOffset;

    private byte[] signingBlock;

    private long CDOffset;

    private long EOCDOffset;

    private EndOfCentralDirectory endOfCentralDirectory;

    private String file;

    private final List<String> suffix4K = new ArrayList<String>() {{
        add(".so");
        add(".abc");
    }};

    private final short unCompressMethod = 0;

    public Zip(File file) throws IOException {
        long start = System.currentTimeMillis();
        this.file = file.getPath();
        // 1. get eocd data
        endOfCentralDirectory = getZipEndOfCentralDirectory(file);
        long EOCD = System.currentTimeMillis();
        LOGGER.info("read EOCD use " + (EOCD - start) + "ms");
        // 2. use eocd's cd offset, get cd data
        getZipCentralDirectory(file);
        long CD = System.currentTimeMillis();
        LOGGER.info("read CD use " + (CD - EOCD) + "ms");
        // 3. use cd's entry offset and file size, get entry data
        getZipEntries(file);
        long entry = System.currentTimeMillis();
        LOGGER.info("read entry use " + (entry - CD) + "ms");
        // 4. file all data - eocd - cd - entry = sign block
        signingBlock = getSigningBlock(file);
        long signBlock = System.currentTimeMillis();
        LOGGER.info("read signBlock use " + (signBlock - entry) + "ms");
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

    private void getZipCentralDirectory(File file) throws IOException {
        zipEntries = new ArrayList<>(endOfCentralDirectory.getCDTotal());
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
            ZipEntry entry = new ZipEntry();
            entry.setCentralDirectory(cd);
            zipEntries.add(entry);
            offset += CentralDirectory.cdLength + cd.getFileNameLength() + cd.getExtraLength() + cd.getCommentLength();
        }
    }

    private byte[] getSigningBlock(File file) throws IOException {
        return FileUtils.readFileByOffsetAndLength(file, signingOffset, CDOffset - signingOffset);
    }

    private void getZipEntries(File file) throws IOException {
        for (ZipEntry entry : zipEntries) {
            CentralDirectory cd = entry.getCentralDirectory();
            long offset = cd.getOffset();
            long fileSize = cd.getCompressedSize();
            short flag = cd.getFlag();
            short i = 0x08;
            // set desc null flag
            boolean descFlag = (flag & i) != 0;
            entry.setZipEntryData(ZipEntryData.initZipEntry(file, offset, fileSize, descFlag));
        }
        ZipEntry endEntry = zipEntries.get(zipEntries.size() - 1);
        CentralDirectory endCD = endEntry.getCentralDirectory();
        ZipEntryData endEntryData = endEntry.getZipEntryData();
        signingOffset = endCD.getOffset() + endEntryData.getLength();
    }

    public void toFile(String file) throws IOException {
        File f = new File(file);
        if (!f.exists()) {
            f.createNewFile();
        }
        FileUtils.write(new byte[]{}, f);
        long start = System.currentTimeMillis();

        for (ZipEntry entry : zipEntries) {
            ZipEntryData zipEntryData = entry.getZipEntryData();
            FileUtils.writeByteToOutFile(zipEntryData.getZipEntryHeader().toBytes(), file);
            FileUtils.writeFileByOffsetToFile(this.file, file, zipEntryData.getFileOffset(), zipEntryData.getFileSize());
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
        long end = System.currentTimeMillis();
        LOGGER.info("write file use " + (end - start) + "ms");
    }

    public void alignment() throws ZipException {
        for (ZipEntry entry : zipEntries) {
            ZipEntryData zipEntryData = entry.getZipEntryData();
            short method = zipEntryData.getZipEntryHeader().getMethod();
            // only align uncompressed entry.
            if (method != unCompressMethod) {
                continue;
            }
            // some file align 4096 byte.
            if (is4kAlignSuffix(zipEntryData.getZipEntryHeader().getFileName())) {
                short align4kBytes = 4096;
                short alignment = zipEntryData.alignment(align4kBytes);
                if (alignment > 0) {
                    int offset = entry.getCentralDirectory().getOffset() + alignment;
                    entry.getCentralDirectory().setOffset(offset);
                    endOfCentralDirectory.setOffset(endOfCentralDirectory.getOffset() + alignment);
                }
            } else {
            // other file align 4 byte.
                short align4Bytes = 4;
                short alignment = zipEntryData.alignment(align4Bytes);
                if (alignment > 0) {
                    int offset = entry.getCentralDirectory().getOffset() + alignment;
                    entry.getCentralDirectory().setOffset(offset);
                    endOfCentralDirectory.setOffset(endOfCentralDirectory.getOffset() + alignment);
                }
            }
        }
    }

    public void sort() {
        int unCompressOffset = 0;
        int CompressOffset = zipEntries.size() - 1;
        int pointer = 0;
        // sort uncompress file (so, abc) - other uncompress file - compress file
        while (pointer <= CompressOffset) {
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
                ZipEntry temp = zipEntries.get(CompressOffset);
                zipEntries.set(CompressOffset, zipEntries.get(pointer));
                zipEntries.set(pointer, temp);
                CompressOffset--;
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

    public List<ZipEntry> getZipEntries() {
        return zipEntries;
    }

    public void setZipEntries(List<ZipEntry> zipEntries) {
        this.zipEntries = zipEntries;
    }
}