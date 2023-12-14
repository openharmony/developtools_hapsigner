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
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * resolve zip data
 *
 * @since 2023/12/02
 */
public class Zip {
    private static final Map<String, String> suffixRegex = new HashMap<String, String>() {{
        put("so", ".*\\.so(\\.[0-9]*)*$");
        put("abc", ".*\\.abc$");
        put("an", ".*\\.an$");
    }};

    private List<ZipEntry> zipEntries;

    private long signingOffset;

    private byte[] signingBlock;

    private long cDOffset;

    private long eOCDOffset;

    private EndOfCentralDirectory endOfCentralDirectory;

    private String file;

    private final short unCompressMethod = 0;

    /**
     * create Zip by file
     *
     * @param file file
     */
    public Zip(File file) {
        try {
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
        } catch (IOException e) {
            CustomException.throwException(ERROR.ZIP_ERROR, e.getMessage());
        }
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
            eocd = EndOfCentralDirectory.initEOCDByBytes(bytes, start);
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
            CentralDirectory cd = CentralDirectory.initCentralDirectory(bf);
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
            short mask = 0x08;
            // set desc null flag
            boolean hasDesc = (flag & mask) != 0;
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
     */
    public void toFile(String file) {
        try {
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
            boolean is4KAlign = true;
            for (ZipEntry entry : zipEntries) {
                ZipEntryData zipEntryData = entry.getZipEntryData();
                short method = zipEntryData.getZipEntryHeader().getMethod();
                if (method != unCompressMethod && !is4KAlign) {
                    // only align uncompressed entry and the first compress entry.
                    break;
                }
                int alignBytes;
                if (isRunnableFile(zipEntryData.getZipEntryHeader().getFileName())) {
                    // .abc and .so file align 4096 byte.
                    alignBytes = 4096;
                } else {
                    // the first file after runnable file, align 4096 byte.
                    if (is4KAlign) {
                        alignBytes = 4096;
                        is4KAlign = false;
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
     * sort uncompress entry in the front.
     */
    private void sort() {
        int unCompressOffset = 0;
        int compressOffset = zipEntries.size() - 1;
        int pointer = 0;
        // sort uncompress file (so, abc, an) - other uncompress file - compress file
        while (pointer <= compressOffset) {
            ZipEntry entry = zipEntries.get(pointer);
            if (isRunnableFile(entry.getZipEntryData().getZipEntryHeader().getFileName())
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
        offset += signingBlock.length;
        cDOffset = offset;
        endOfCentralDirectory.setOffset(offset);
        endOfCentralDirectory.setcDSize(cdLength);
        offset += cdLength;
        eOCDOffset = offset;
    }

    /**
     * regex filename
     *
     * @param name filename
     * @return boolean
     */
    public static boolean isRunnableFile(String name) {
        for (String regex : suffixRegex.values()) {
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(name);
            if (matcher.matches()) {
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

    public short getUnCompressMethod() {
        return unCompressMethod;
    }
}