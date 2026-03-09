/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.hap.verify;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * ELF sign info structure for parsing .codesign section.
 * Corresponds to C++ struct ElfSignInfo in verify_elf.h
 *
 * struct ElfSignInfo {
 *     uint32_t type;
 *     uint32_t length;
 *     uint8_t  version;
 *     uint8_t  hashAlgorithm;
 *     uint8_t  logBlockSize;
 *     uint8_t  saltSize;
 *     uint32_t signSize;
 *     uint64_t dataSize;
 *     uint8_t  rootHash[64];
 *     uint8_t  salt[32];
 *     uint32_t flags;
 *     uint8_t  reserved_1[12];
 *     uint8_t  reserved_2[127];
 *     uint8_t  csVersion;
 *     uint8_t  signature[0];
 * };
 *
 * @since 2026/3/5
 */
public class ElfSignInfo {
    private static final int ROOT_HASH_SIZE = 64;
    private static final int SALT_SIZE = 32;
    private static final int RESERVED_1_SIZE = 12;
    private static final int RESERVED_2_SIZE = 127;

    private int type;
    private int length;
    private byte version;
    private byte hashAlgorithm;
    private byte logBlockSize;
    private byte saltSize;
    private int signSize;
    private long dataSize;
    private byte[] rootHash;
    private byte[] salt;
    private int flags;
    private byte[] reserved1;
    private byte[] reserved2;
    private byte csVersion;
    private byte[] signature;

    public ElfSignInfo() {
        this.rootHash = new byte[ROOT_HASH_SIZE];
        this.salt = new byte[SALT_SIZE];
        this.reserved1 = new byte[RESERVED_1_SIZE];
        this.reserved2 = new byte[RESERVED_2_SIZE];
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public byte getVersion() {
        return version;
    }

    public void setVersion(byte version) {
        this.version = version;
    }

    public byte getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(byte hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public byte getLogBlockSize() {
        return logBlockSize;
    }

    public void setLogBlockSize(byte logBlockSize) {
        this.logBlockSize = logBlockSize;
    }

    public byte getSaltSize() {
        return saltSize;
    }

    public void setSaltSize(byte saltSize) {
        this.saltSize = saltSize;
    }

    public int getSignSize() {
        return signSize;
    }

    public void setSignSize(int signSize) {
        this.signSize = signSize;
    }

    public long getDataSize() {
        return dataSize;
    }

    public void setDataSize(long dataSize) {
        this.dataSize = dataSize;
    }

    public byte[] getRootHash() {
        return rootHash;
    }

    public void setRootHash(byte[] rootHash) {
        if (rootHash != null && rootHash.length == ROOT_HASH_SIZE) {
            System.arraycopy(rootHash, 0, this.rootHash, 0, ROOT_HASH_SIZE);
        }
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        if (salt != null && salt.length == SALT_SIZE) {
            System.arraycopy(salt, 0, this.salt, 0, SALT_SIZE);
        }
    }

    public int getFlags() {
        return flags;
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public byte[] getReserved1() {
        return reserved1;
    }

    public byte[] getReserved2() {
        return reserved2;
    }

    public byte getCsVersion() {
        return csVersion;
    }

    public void setCsVersion(byte csVersion) {
        this.csVersion = csVersion;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    /**
     * Parse ElfSignInfo from byte array.
     *
     * @param data byte array containing ElfSignInfo
     * @return ElfSignInfo object
     * @throws IllegalArgumentException if data is invalid
     */
    public static ElfSignInfo fromByteArray(byte[] data) {
        if (data == null || data.length < getHeaderSize()) {
            throw new IllegalArgumentException("Invalid ElfSignInfo data: too short");
        }

        ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        ElfSignInfo info = new ElfSignInfo();
        info.type = buffer.getInt();
        info.length = buffer.getInt();
        info.version = buffer.get();
        info.hashAlgorithm = buffer.get();
        info.logBlockSize = buffer.get();
        info.saltSize = buffer.get();
        info.signSize = buffer.getInt();
        info.dataSize = buffer.getLong();

        buffer.get(info.rootHash);
        buffer.get(info.salt);
        info.flags = buffer.getInt();
        buffer.get(info.reserved1);
        buffer.get(info.reserved2);
        info.csVersion = buffer.get();

        int signatureOffset = getHeaderSize();
        if (data.length > signatureOffset) {
            info.signature = new byte[data.length - signatureOffset];
            buffer.get(info.signature);
        }

        return info;
    }

    /**
     * Get the size of the fixed header part (excluding signature).
     *
     * @return header size in bytes
     */
    public static int getHeaderSize() {
        return 4 + 4 + 1 + 1 + 1 + 1 + 4 + 8 + ROOT_HASH_SIZE + SALT_SIZE + 4 + RESERVED_1_SIZE + RESERVED_2_SIZE + 1;
    }

    /**
     * Get total size including signature.
     *
     * @return total size in bytes
     */
    public int getTotalSize() {
        return getHeaderSize() + (signature != null ? signature.length : 0);
    }
}
