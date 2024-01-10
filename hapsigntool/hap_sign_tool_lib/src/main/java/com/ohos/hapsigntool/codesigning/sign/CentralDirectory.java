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

package com.ohos.hapsigntool.codesigning.sign;

import com.ohos.hapsigntool.utils.FileUtils;

import org.bouncycastle.util.Strings;

import java.util.Locale;
import java.util.zip.ZipEntry;

/**
 * Central directory structure
 * further reference to <a herf="https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT">Zip Format</a>
 *
 * @since 2023/09/14
 */
public class CentralDirectory {
    /**
     * Byte size of all fields before "compression method" in central directory structure
     */
    public static final int BYTE_SIZE_BEFORE_COMPRESSION_METHOD = 10;

    /**
     * Byte size of all fields between "compression method" and "file comment length" in central directory structure
     */
    public static final int BYTE_SIZE_BETWEEN_COMPRESSION_MODE_AND_FILE_SIZE = 16;

    /**
     * Byte size of all fields between "file comment length" and
     * "relative offset of local header" in central directory structure
     */
    public static final int BYTE_SIZE_BETWEEN_FILE_COMMENT_LENGTH_AND_LOCHDR_RELATIVE_OFFSET = 8;

    private final char compressionMethod;

    private final char fileNameLength;

    private final char extraFieldLength;

    private final char fileCommentLength;

    private final long relativeOffsetOfLocalHeader;

    private final byte[] fileName;

    public CentralDirectory(Builder builder) {
        this.compressionMethod = builder.compressionMethod;
        this.fileNameLength = builder.fileNameLength;
        this.extraFieldLength = builder.extraFieldLength;
        this.fileCommentLength = builder.fileCommentLength;
        this.relativeOffsetOfLocalHeader = builder.relativeOffsetOfLocalHeader;
        this.fileName = builder.fileName;
    }

    /**
     * Return true if entry is an executable file, i.e. abc or so
     *
     * @return true if entry is an executable file
     */
    public boolean isCodeFile() {
        return FileUtils.isRunnableFile(this.getFileName());
    }

    /**
     * Return true if zip entry is uncompressed
     *
     * @return true if zip entry is uncompressed
     */
    public boolean isUncompressed() {
        return this.compressionMethod == ZipEntry.STORED;
    }

    public String getFileName() {
        return Strings.fromByteArray(this.fileName);
    }

    public long getRelativeOffsetOfLocalHeader() {
        return relativeOffsetOfLocalHeader;
    }

    /**
     * Sum byte size of three variable fields: file name, extra field, file comment
     *
     * @return Sum byte size of three variable fields
     */
    public char getFileNameLength() {
        return fileNameLength;
    }

    public char getExtraFieldLength() {
        return extraFieldLength;
    }

    /**
     * Return a string representation of the object
     *
     * @return string representation of the object
     */
    public String toString() {
        return String.format(Locale.ROOT,
            "CentralDirectory:compressionMode(%d), fileName(%s), relativeOffsetOfLocalHeader(%d), "
                + "fileNameLength(%d), extraFieldLength(%d), fileCommentLength(%d)", (int) this.compressionMethod,
            this.getFileName(), this.relativeOffsetOfLocalHeader, (int) this.fileNameLength,
            (int) this.extraFieldLength, (int) this.fileCommentLength);
    }

    /**
     * Builder of CentralDirectory class
     */
    public static class Builder {
        private char compressionMethod;

        private char fileNameLength;

        private char extraFieldLength;

        private char fileCommentLength;

        private long relativeOffsetOfLocalHeader;

        private byte[] fileName;

        public Builder setCompressionMethod(char compressionMethod) {
            this.compressionMethod = compressionMethod;
            return this;
        }

        public Builder setFileNameLength(char fileNameLength) {
            this.fileNameLength = fileNameLength;
            return this;
        }

        public Builder setExtraFieldLength(char extraFieldLength) {
            this.extraFieldLength = extraFieldLength;
            return this;
        }

        public Builder setFileCommentLength(char fileCommentLength) {
            this.fileCommentLength = fileCommentLength;
            return this;
        }

        public Builder setRelativeOffsetOfLocalHeader(long relativeOffsetOfLocalHeader) {
            this.relativeOffsetOfLocalHeader = relativeOffsetOfLocalHeader;
            return this;
        }

        public Builder setFileName(byte[] fileName) {
            this.fileName = fileName;
            return this;
        }

        /**
         * Create a CentralDirectory object
         *
         * @return a CentralDirectory object
         */
        public CentralDirectory build() {
            return new CentralDirectory(this);
        }
    }
}
