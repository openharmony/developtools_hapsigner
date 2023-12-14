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

import com.ohos.hapsigntool.error.CustomException;
import com.ohos.hapsigntool.error.ERROR;
import com.ohos.hapsigntool.error.ZipException;
import com.ohos.hapsigntool.utils.FileUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * resolve zip data
 *
 * @since 2023/12/02
 */
public class Zip {
    /**
     * file is uncompress file flag
     */
    public static final int FILE_UNCOMPRESS_METHOD_FLAG = 0;

    private List<ZipEntry> zipEntries;

    private long signingOffset;

    private byte[] signingBlock;

    private long cDOffset;

    private long eOCDOffset;

    private EndOfCentralDirectory endOfCentralDirectory;

    private String file;

    private final short unCompressMethod = 0;

    private final int MAX_COMMENT_LENGTH = 65535;


    /**
     * create Zip by file
     *
     * @param inputFile file
     */
    public Zip(File inputFile) {
        try {
            this.file = inputFile.getPath();
            if (!inputFile.exists()) {
                throw new ZipException("read zip file failed");
            }
            // 1. get eocd data
            endOfCentralDirectory = getZipEndOfCentralDirectory(inputFile);
            // 2. use eocd's cd offset, get cd data
            getZipCentralDirectory(inputFile);
            // 3. use cd's entry offset and file size, get entry data
            getZipEntries(inputFile);
            // 4. file all data - eocd - cd - entry = sign block
            signingBlock = getSigningBlock(inputFile);
        } catch (IOException e) {
            CustomException.throwException(ERROR.ZIP_ERROR, e.getMessage());
        }
    }

    private EndOfCentralDirectory getZipEndOfCentralDirectory(File file) throws IOException {
        if (file.length() < EndOfCentralDirectory.EOCD_LENGTH) {
            throw new ZipException("find zip eocd failed");
        }

        // try to read EOCD without comment
        int eocdLength = EndOfCentralDirectory.EOCD_LENGTH;
        eOCDOffset = file.length() - eocdLength;
        byte[] bytes = FileUtils.readFileByOffsetAndLength(file, eOCDOffset, eocdLength);
        EndOfCentralDirectory eocd = EndOfCentralDirectory.getEOCDByBytes(bytes);
        if (eocd != null) {
            return eocd;
        }

        // try to search EOCD with comment
        long eocdMaxLength = Math.min(EndOfCentralDirectory.EOCD_LENGTH + MAX_COMMENT_LENGTH, file.length());
        eOCDOffset = file.length() - eocdMaxLength;
        bytes = FileUtils.readFileByOffsetAndLength(file, eOCDOffset, eocdMaxLength);
        for (int start = 0; start < eocdMaxLength; start++) {
            eocd = EndOfCentralDirectory.getEOCDByBytes(bytes, start);
            if (eocd != null) {
                eOCDOffset += start;
                return eocd;
            }
        }
        throw new ZipException("read zip failed: can not find eocd in file");
    }

    private void getZipCentralDirectory(File file) throws IOException {
        zipEntries = new ArrayList<>(endOfCentralDirectory.getcDTotal());
        cDOffset = endOfCentralDirectory.getOffset();
        // read full central directory bytes
        byte[] cdBytes = FileUtils.readFileByOffsetAndLength(file, cDOffset, endOfCentralDirectory.getcDSize());
        if (cdBytes.length < CentralDirectory.CD_LENGTH) {
            throw new ZipException("find zip cd failed");
        }
        ByteBuffer bf = ByteBuffer.wrap(cdBytes);
        bf.order(ByteOrder.LITTLE_ENDIAN);
        int offset = 0;
        // one by one format central directory
        while (offset < cdBytes.length) {
            CentralDirectory cd = CentralDirectory.getCentralDirectory(bf);
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
            long unCompressedSize = cd.getUnCompressedSize();
            long compressedSize = cd.getCompressedSize();
            long fileSize = cd.getMethod() == FILE_UNCOMPRESS_METHOD_FLAG ? unCompressedSize : compressedSize;

            entry.setZipEntryData(ZipEntryData.getZipEntry(file, offset, fileSize));
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
     */
    public void toFile(String file) {
        try {
            File f = new File(file);
            if (f.exists()) {
                FileUtils.write(new byte[]{}, f);
            } else {
                f.createNewFile();
            }
        } catch (IOException e) {
            CustomException.throwException(ERROR.ZIP_ERROR, e.getMessage());
        }

        try (FileOutputStream fos = new FileOutputStream(file, true)) {
            for (ZipEntry entry : zipEntries) {
                ZipEntryData zipEntryData = entry.getZipEntryData();
                FileUtils.writeByteToOutFile(zipEntryData.getZipEntryHeader().toBytes(), fos);
                boolean isSuccess = FileUtils.appendWriteFileByOffsetToFile(this.file, file,
                        zipEntryData.getFileOffset(), zipEntryData.getFileSize());
                if (!isSuccess) {
                    throw new ZipException("write zip data failed");
                }
                if (zipEntryData.getDataDescriptor() != null) {
                    FileUtils.writeByteToOutFile(zipEntryData.getDataDescriptor().toBytes(), fos);
                }
            }
            if (signingBlock != null) {
                FileUtils.writeByteToOutFile(signingBlock, fos);
            }
            for (ZipEntry entry : zipEntries) {
                CentralDirectory cd = entry.getCentralDirectory();
                FileUtils.writeByteToOutFile(cd.toBytes(), fos);
            }
            FileUtils.writeByteToOutFile(endOfCentralDirectory.toBytes(), fos);
        } catch (IOException e) {
            CustomException.throwException(ERROR.ZIP_ERROR, e.getMessage());
        }
    }

    /**
     * alignment uncompress entry
     *
     * @param alignment int alignment
     */
    public void alignment(int alignment) {
        try {
            sort();
            boolean isFirstUnRunnableFile = true;
            for (ZipEntry entry : zipEntries) {
                ZipEntryData zipEntryData = entry.getZipEntryData();
                short method = zipEntryData.getZipEntryHeader().getMethod();
                if (method != unCompressMethod && !isFirstUnRunnableFile) {
                    // only align uncompressed entry and the first compress entry.
                    break;
                }
                int alignBytes;
                if (method == unCompressMethod && FileUtils.isRunnableFile(
                        zipEntryData.getZipEntryHeader().getFileName())) {
                    // .abc and .so file align 4096 byte.
                    alignBytes = 4096;
                } else {
                    // the first file after runnable file, align 4096 byte.
                    if (isFirstUnRunnableFile) {
                        alignBytes = 4096;
                        isFirstUnRunnableFile = false;
                    } else {
                        // normal file align 4 byte.
                        alignBytes = alignment;
                    }
                }
                int add = entry.alignment(alignBytes);
                if (add > 0) {
                    resetOffset();
                }
            }
        } catch (ZipException e) {
            CustomException.throwException(ERROR.ZIP_ERROR, e.getMessage());
        }
    }

    /**
     * remove sign block
     */
    public void removeSignBlock() {
        signingBlock = null;
        resetOffset();
    }

    /**
     * sort uncompress entry in the front.
     */
    private void sort() {
        // sort uncompress file (so, abc, an) - other uncompress file - compress file
        zipEntries.sort((entry1, entry2) -> {
            short entry1Method = entry1.getZipEntryData().getZipEntryHeader().getMethod();
            short entry2Method = entry2.getZipEntryData().getZipEntryHeader().getMethod();
            String entry1FileName = entry1.getZipEntryData().getZipEntryHeader().getFileName();
            String entry2FileName = entry2.getZipEntryData().getZipEntryHeader().getFileName();

            if (entry1Method == unCompressMethod && entry2Method == unCompressMethod) {
                if (FileUtils.isRunnableFile(entry1FileName) && FileUtils.isRunnableFile(entry2FileName)) {
                    return entry1FileName.compareTo(entry2FileName);
                } else if (FileUtils.isRunnableFile(entry1FileName)) {
                    return -1;
                } else if (FileUtils.isRunnableFile(entry2FileName)) {
                    return 1;
                }
            } else if (entry1Method == unCompressMethod) {
                return -1;
            } else if (entry2Method == unCompressMethod) {
                return 1;
            }
            return entry1FileName.compareTo(entry2FileName);
        });
        resetOffset();
    }

    private void resetOffset() {
        long offset = 0L;
        long cdLength = 0L;
        for (ZipEntry entry : zipEntries) {
            entry.getCentralDirectory().setOffset(offset);
            offset += entry.getZipEntryData().getLength();
            cdLength += entry.getCentralDirectory().getLength();
        }
        if (signingBlock != null) {
            offset += signingBlock.length;
        }
        cDOffset = offset;
        endOfCentralDirectory.setOffset(offset);
        endOfCentralDirectory.setcDSize(cdLength);
        offset += cdLength;
        eOCDOffset = offset;
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

    public short getUnCompressMethod() {
        return unCompressMethod;
    }
}