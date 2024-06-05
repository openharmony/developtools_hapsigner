/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.hap.sign;

import com.ohos.hapsigntool.entity.ContentDigestAlgorithm;
import com.ohos.hapsigntool.entity.Options;
import com.ohos.hapsigntool.entity.SignatureAlgorithm;
import com.ohos.hapsigntool.hap.config.SignerConfig;
import com.ohos.hapsigntool.entity.Pair;
import com.ohos.hapsigntool.hap.entity.SigningBlock;
import com.ohos.hapsigntool.error.HapFormatException;
import com.ohos.hapsigntool.error.SignatureException;
import com.ohos.hapsigntool.utils.FileUtils;
import com.ohos.hapsigntool.hap.utils.HapUtils;
import com.ohos.hapsigntool.utils.StringUtils;
import com.ohos.hapsigntool.zip.ZipDataInput;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.DigestException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.stream.Collectors;

/**
 *
 * Hap Signature Scheme signer
 *
 * @since 2021/12/21
 */
public abstract class SignHap {
    private static final int STORED_ENTRY_SO_ALIGNMENT = 4096;
    private static final int BUFFER_LENGTH = 4096;
    private static final int BLOCK_COUNT = 4;
    private static final int BLOCK_MAGIC = 16;
    private static final int BLOCK_VERSION = 4;
    private static final long INIT_OFFSET_LEN = 4L;
    private static final int OPTIONAL_TYPE_SIZE = 4;
    private static final int OPTIONAL_LENGTH_SIZE = 4;
    private static final int OPTIONAL_OFFSET_SIZE = 4;

    private SignHap() {}

    /**
     * Copy the jar file and align the storage entries.
     *
     * @param in input hap-file which is opened as a jar-file.
     * @param out output stream of jar.
     * @param timestamp ZIP file timestamps
     * @param defaultAlignment default value of alignment.
     * @throws IOException io error.
     * @throws HapFormatException hap format error.
     */
    public static void copyFiles(JarFile in,
        JarOutputStream out, long timestamp, int defaultAlignment) throws IOException, HapFormatException {
        // split compressed and uncompressed
        List<JarEntry> entryListStored = in.stream()
                .filter(jarFile -> jarFile.getMethod() == JarEntry.STORED).collect(Collectors.toList());

        // uncompressed special files and place in front
        entryListStored = storedEntryListOfSort(entryListStored);
        long offset = INIT_OFFSET_LEN;
        String lastAlignmentEntryName = "";
        for (JarEntry inEntry : entryListStored) {
            String entryName = inEntry.getName();
            if (!FileUtils.isRunnableFile(entryName)) {
                lastAlignmentEntryName = entryName;
                break;
            }
        }
        for (JarEntry inEntry : entryListStored) {
            if (inEntry == null) {
                continue;
            }

            offset += JarFile.LOCHDR;

            JarEntry outEntry = getJarEntry(timestamp, inEntry);
            offset += outEntry.getName().length();

            int alignment = getStoredEntryDataAlignment(inEntry.getName(), defaultAlignment, lastAlignmentEntryName);
            if (alignment > 0 && (offset % alignment != 0)) {
                int needed = alignment - (int) (offset % alignment);
                outEntry.setExtra(new byte[needed]);
                offset += needed;
            }

            out.putNextEntry(outEntry);
            offset = writeOutputStreamAndGetOffset(in, out, inEntry, offset);
        }
        List<JarEntry> entryListNotStored = in.stream()
                .filter(jarFile -> jarFile.getMethod() != JarEntry.STORED).collect(Collectors.toList());
        // process byte alignment of the first compressed file
        boolean isAlignmentFlag = StringUtils.isEmpty(lastAlignmentEntryName);
        if (isAlignmentFlag) {
            if (entryListNotStored.isEmpty()) {
                throw new HapFormatException("Hap format is error, file missing");
            }
            JarEntry firstEntry = entryListNotStored.get(0);
            offset += JarFile.LOCHDR;
            JarEntry outEntry = getFirstJarEntry(firstEntry, offset, timestamp);
            out.putNextEntry(outEntry);
            byte[] buffer = new byte[BUFFER_LENGTH];
            writeOutputStream(in, out, firstEntry, buffer);
        }

        copyFilesExceptStoredFile(entryListNotStored, in, out, timestamp, isAlignmentFlag);
    }

    /**
     * uncompressed special files are placed in front
     *
     * @param entryListStored stored file entry list
     * @return List<JarEntry> jarEntryList
     */
    private static List<JarEntry> storedEntryListOfSort(List<JarEntry> entryListStored) {
        return entryListStored.stream().sorted((entry1, entry2) -> {
            String name1 = entry1.getName();
            String name2 = entry2.getName();
            // files ending with .abc or .so are placed before other files
            boolean isSpecial1 = FileUtils.isRunnableFile(name1);
            boolean isSpecial2 = FileUtils.isRunnableFile(name2);
            if (isSpecial1 && !isSpecial2) {
                return -1;
            } else if (!isSpecial1 && isSpecial2) {
                return 1;
            } else {
                // if all files are special files or none of them are special files,the files are sorted lexically
                return name1.compareTo(name2);
            }
        }).collect(Collectors.toList());
    }

    private static JarEntry getFirstJarEntry(JarEntry firstEntry, long offset, long timestamp) {
        long currentOffset = offset;
        JarEntry outEntry = getJarEntry(timestamp, firstEntry);
        currentOffset += outEntry.getName().length();
        if (currentOffset % STORED_ENTRY_SO_ALIGNMENT != 0) {
            int needed = STORED_ENTRY_SO_ALIGNMENT - (int) (currentOffset % STORED_ENTRY_SO_ALIGNMENT);
            outEntry.setExtra(new byte[needed]);
        }
        return outEntry;
    }

    /**
     * write first not stored entry to outputStream
     *
     * @param in jar file
     * @param out jarOutputStream
     * @param firstEntry jarEntry
     * @param buffer byte[]
     * @throws IOException IOExpcetion
     */
    private static void writeOutputStream(JarFile in, JarOutputStream out, JarEntry firstEntry, byte[] buffer)
            throws IOException {
        try (InputStream data = in.getInputStream(firstEntry)) {
            int num;
            while ((num = data.read(buffer)) > 0) {
                out.write(buffer, 0, num);
            }
            out.flush();
        }
    }

    private static long writeOutputStreamAndGetOffset(JarFile in, JarOutputStream out, JarEntry inEntry, long offset)
            throws IOException {
        byte[] buffer = new byte[BUFFER_LENGTH];
        long currentOffset = offset;
        try (InputStream data = in.getInputStream(inEntry)) {
            int num;
            while ((num = data.read(buffer)) > 0) {
                out.write(buffer, 0, num);
                currentOffset += num;
            }
            out.flush();
        }
        return currentOffset;
    }

    private static JarEntry getJarEntry(long timestamp, JarEntry inEntry) {
        JarEntry outEntry = new JarEntry(inEntry);
        outEntry.setTime(timestamp);

        outEntry.setComment(null);
        outEntry.setExtra(null);
        return outEntry;
    }

    private static void copyFilesExceptStoredFile(List<JarEntry> entryListNotStored, JarFile in,
        JarOutputStream out, long timestamp, boolean isAlignmentFlag) throws IOException {
        byte[] buffer = new byte[BUFFER_LENGTH];
        int index = 0;
        if (isAlignmentFlag) {
            index = 1;
        }
        for (; index < entryListNotStored.size(); index++) {
            JarEntry inEntry = entryListNotStored.get(index);
            if (inEntry == null || inEntry.getMethod() == JarEntry.STORED) {
                continue;
            }

            JarEntry outEntry = new JarEntry(inEntry.getName());
            outEntry.setTime(timestamp);
            out.putNextEntry(outEntry);
            writeOutputStream(in, out, inEntry, buffer);
        }
    }

    /**
     * If store entry is end with '.so', use 4096-alignment, otherwise, use default-alignment.
     *
     * @param entryName name of entry
     * @param defaultAlignment default value of alignment.
     * @param lastAlignmentEntryName lastAlignmentEntryName
     * @return value of alignment.
     */
    private static int getStoredEntryDataAlignment(String entryName, int defaultAlignment,
                                                   String lastAlignmentEntryName) {
        if (defaultAlignment <= 0) {
            return 0;
        }
        if (!StringUtils.isEmpty(lastAlignmentEntryName) && entryName.equals(lastAlignmentEntryName)) {
            return STORED_ENTRY_SO_ALIGNMENT;
        }
        if (FileUtils.isRunnableFile(entryName)) {
            return STORED_ENTRY_SO_ALIGNMENT;
        }
        return defaultAlignment;
    }

    private static byte[] getHapSigningBlock(
            Set<ContentDigestAlgorithm> contentDigestAlgorithms,
            List<SigningBlock> optionalBlocks,
            SignerConfig signerConfig,
            ZipDataInput[] hapData)
            throws SignatureException {
        /**
         * Compute digests of Hap contents
         * Sign the digests and wrap the signature and signer info into the Hap Signing Block
         */
        byte[] hapSignatureBytes = null;
        try {
            Map<ContentDigestAlgorithm, byte[]> contentDigests =
                    HapUtils.computeDigests(contentDigestAlgorithms, hapData, optionalBlocks);
            hapSignatureBytes = generateHapSigningBlock(signerConfig, contentDigests, optionalBlocks);
        } catch (DigestException | IOException e) {
            throw new SignatureException("Failed to compute digests of HAP", e);
        }
        return hapSignatureBytes;
    }

    private static byte[] generateHapSigningBlock(
            SignerConfig signerConfig,
            Map<ContentDigestAlgorithm, byte[]> contentDigests,
            List<SigningBlock> optionalBlocks)
            throws SignatureException {
        byte[] hapSignatureSchemeBlock = generateHapSignatureSchemeBlock(signerConfig, contentDigests);
        return generateHapSigningBlock(hapSignatureSchemeBlock, optionalBlocks, signerConfig.getCompatibleVersion());
    }

    private static byte[] generateHapSigningBlock(byte[] hapSignatureSchemeBlock,
                                                  List<SigningBlock> optionalBlocks, int compatibleVersion) {
        // FORMAT:
        // Proof-of-Rotation pairs(optional):
        // uint32:type
        // uint32:length
        // uint32:offset
        // Property pairs(optional):
        // uint32:type
        // uint32:length
        // uint32:offset
        // Profile capability pairs(optional):
        // uint32:type
        // uint32:length
        // uint32:offset
        // length bytes : app signing pairs
        // uint32:type
        // uint32:length
        // uint32:offset
        // repeated ID-value pairs(reserved extensions):
        // length bytes : Proof-of-Rotation values
        // length bytes : property values
        // length bytes : profile capability values
        // length bytes : signature schema values
        // uint64: size
        // uint128: magic
        // uint32: version
        long optionalBlockSize = 0L;
        for (SigningBlock optionalBlock : optionalBlocks) {
            optionalBlockSize += optionalBlock.getLength();
        }
        long resultSize =
                ((OPTIONAL_TYPE_SIZE + OPTIONAL_LENGTH_SIZE + OPTIONAL_OFFSET_SIZE) * (optionalBlocks.size() + 1))
                        + optionalBlockSize // optional pair
                        + hapSignatureSchemeBlock.length // App signing pairs
                        + BLOCK_COUNT // block count
                        + HapUtils.BLOCK_SIZE // size
                        + BLOCK_MAGIC // magic
                        + BLOCK_VERSION; // version
        if (resultSize > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("HapSigningBlock out of range : " + resultSize);
        }
        ByteBuffer result = ByteBuffer.allocate((int) resultSize);
        result.order(ByteOrder.LITTLE_ENDIAN);

        Map<Integer, Integer> typeAndOffsetMap = new HashMap<Integer, Integer>();
        int currentOffset = ((OPTIONAL_TYPE_SIZE + OPTIONAL_LENGTH_SIZE
                + OPTIONAL_OFFSET_SIZE) * (optionalBlocks.size() + 1));
        int currentOffsetInBlockValue = 0;
        int blockValueSizes = (int) (optionalBlockSize + hapSignatureSchemeBlock.length);
        byte[] blockValues = new byte[blockValueSizes];

        for (SigningBlock optionalBlock : optionalBlocks) {
            System.arraycopy(
                    optionalBlock.getValue(), 0, blockValues, currentOffsetInBlockValue, optionalBlock.getLength());
            typeAndOffsetMap.put(optionalBlock.getType(), currentOffset);
            currentOffset += optionalBlock.getLength();
            currentOffsetInBlockValue += optionalBlock.getLength();
        }

        System.arraycopy(
                hapSignatureSchemeBlock, 0, blockValues, currentOffsetInBlockValue, hapSignatureSchemeBlock.length);
        typeAndOffsetMap.put(HapUtils.HAP_SIGNATURE_SCHEME_V1_BLOCK_ID, currentOffset);

        extractedResult(optionalBlocks, result, typeAndOffsetMap);
        result.putInt(HapUtils.HAP_SIGNATURE_SCHEME_V1_BLOCK_ID); // type
        result.putInt(hapSignatureSchemeBlock.length); // length
        int offset = typeAndOffsetMap.get(HapUtils.HAP_SIGNATURE_SCHEME_V1_BLOCK_ID);
        result.putInt(offset); // offset
        result.put(blockValues);
        result.putInt(optionalBlocks.size() + 1); // Signing block count
        result.putLong(resultSize); // length of hap signing block
        result.put(HapUtils.getHapSigningBlockMagic(compatibleVersion)); // magic
        result.putInt(HapUtils.getHapSigningBlockVersion(compatibleVersion)); // version
        return result.array();
    }

    private static void extractedResult(List<SigningBlock> optionalBlocks, ByteBuffer result,
                                        Map<Integer, Integer> typeAndOffsetMap) {
        int offset;
        for (SigningBlock optionalBlock : optionalBlocks) {
            result.putInt(optionalBlock.getType()); // type
            result.putInt(optionalBlock.getLength()); // length
            offset = typeAndOffsetMap.get(optionalBlock.getType());
            result.putInt(offset); // offset
        }
    }

    private static byte[] generateHapSignatureSchemeBlock(
            SignerConfig signerConfig, Map<ContentDigestAlgorithm, byte[]> contentDigests) throws SignatureException {
        byte[] signerBlock = null;
        try {
            signerBlock = generateSignerBlock(signerConfig, contentDigests);
        } catch (SignatureException e) {
            throw new SignatureException("generate SignerBlock failed"
                    + "\nSolutions:"
                    + "\n> maybe your param keyAlias is incorrect, please input a correct sign keyAlias"
                    + "\n> maybe your certificate is incorrect, please check your certificate match the keyAlias"
                    + "\n> keystore maybe created by a late JDK version, please update your JDK version", e);
        }
        return signerBlock;
    }

    private static byte[] generateSignerBlock(
            SignerConfig signerConfig, Map<ContentDigestAlgorithm, byte[]> contentDigests) throws SignatureException {
        String mode = signerConfig.getOptions().getString(Options.MODE);
        if (!("remoteSign".equalsIgnoreCase(mode)) && signerConfig.getCertificates().isEmpty()) {
            throw new SignatureException("No certificates configured for signer");
        }

        List<Pair<Integer, byte[]>> digests =
                new ArrayList<Pair<Integer, byte[]>>(signerConfig.getSignatureAlgorithms().size());
        for (SignatureAlgorithm signatureAlgorithm : signerConfig.getSignatureAlgorithms()) {
            ContentDigestAlgorithm contentDigestAlgorithm = signatureAlgorithm.getContentDigestAlgorithm();
            byte[] contentDigest = contentDigests.get(contentDigestAlgorithm);
            if (contentDigest == null) {
                throw new SignatureException(
                        contentDigestAlgorithm.getDigestAlgorithm()
                                + " content digest for "
                                + signatureAlgorithm.getSignatureAlgAndParams().getFirst()
                                + " not computed");
            }
            digests.add(Pair.create(signatureAlgorithm.getId(), contentDigest));
        }
        byte[] unsignedHapDigest = HapUtils.encodeListOfPairsToByteArray(digests);
        return Pkcs7Generator.BC.generateSignedData(unsignedHapDigest, signerConfig);
    }

    /**
     * Signs the provided Hap using Hap Signature Scheme and returns the
     * signed block as an array of ByteBuffer
     *
     * @param contents Hap content before ZIP CD
     * @param signerConfig signer config
     * @param optionalBlocks optional blocks
     * @return signed block
     * @throws SignatureException if an error occurs when sign hap file.
     */
    public static byte[] sign(ZipDataInput[] contents, SignerConfig signerConfig, List<SigningBlock> optionalBlocks)
            throws SignatureException {
        Set<ContentDigestAlgorithm> contentDigestAlgorithms = new HashSet<ContentDigestAlgorithm>();
        for (SignatureAlgorithm signatureAlgorithm : signerConfig.getSignatureAlgorithms()) {
            contentDigestAlgorithms.add(signatureAlgorithm.getContentDigestAlgorithm());
        }
        return getHapSigningBlock(contentDigestAlgorithms, optionalBlocks, signerConfig, contents);
    }
}
