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

package com.ohos.hapsigntool.codesigning.sign;

import com.ohos.hapsigntool.codesigning.exception.CodeSignErrMsg;
import com.ohos.hapsigntool.codesigning.exception.CodeSignException;
import com.ohos.hapsigntool.codesigning.exception.FsVerityDigestException;
import com.ohos.hapsigntool.codesigning.fsverity.FsVerityDescriptor;
import com.ohos.hapsigntool.codesigning.fsverity.FsVerityDescriptorWithSign;
import com.ohos.hapsigntool.codesigning.fsverity.FsVerityGenerator;
import com.ohos.hapsigntool.hap.config.SignerConfig;
import com.ohos.hapsigntool.signer.LocalSigner;
import com.ohos.hapsigntool.utils.LogUtils;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

/**
 * core functions of code signing
 *
 * @since 2023/06/05
 */
public class CodeSigning {
    /**
     * Self sign flag value (1 << 4)
     */
    private static final int FLAG_SELF_SIGN = 1 << 4;

    /**
     * ELF code sign version
     */
    private static final byte ELF_CODE_SIGN_VERSION = 0x3;

    /**
     * Minimum cert chain size for GetOwnerIdFromCert
     */
    private static final int MIN_CERT_CHAIN_SIZE = 2;

    private static final LogUtils LOGGER = new LogUtils(CodeSigning.class);

    private final SignerConfig signConfig;

    private final boolean selfSign;

    /**
     * provide code sign functions to sign a hap
     *
     * @param signConfig configuration of sign
     */
    public CodeSigning(SignerConfig signConfig) {
        this(signConfig, false);
    }

    /**
     * provide code sign functions to sign an ELF file with selfSign support
     *
     * @param signConfig configuration of sign
     * @param selfSign whether enable self sign mode
     */
    public CodeSigning(SignerConfig signConfig, boolean selfSign) {
        this.signConfig = signConfig;
        this.selfSign = selfSign;
    }

    /**
     * Sign the given elf file, and pack all signature into output file
     * 1. Open file and calculate flags (including selfSign flag)
     * 2. Generate fs-verity digest
     * 3. If selfSign: use descriptorDigest as signature
     *    If normal: generate PKCS7 signature with ownerID from cert
     * 4. Build FsVerityDescriptor with flags and csVersion
     * 5. Return code sign block bytes
     *
     * @param input file to sign
     * @param offset position of codesign block based on start of the file
     * @return byte array of code sign block
     * @throws CodeSignException code signing exception
     * @throws IOException io error
     * @throws FsVerityDigestException computing FsVerity digest error
     */
    public byte[] getElfCodeSignBlock(File input, long offset)
        throws CodeSignException, FsVerityDigestException, IOException {
        LOGGER.info("Start to sign elf code.");
        long fileSize = input.length();

        // Calculate flags: include FLAG_SELF_SIGN if in selfSign mode
        int flags = 0;
        if (selfSign) {
            flags = flags | FLAG_SELF_SIGN;
            LOGGER.info("Self-sign mode enabled, setting FLAG_SELF_SIGN");
        }

        try (FileInputStream inputStream = new FileInputStream(input)) {
            FsVerityGenerator fsVerityGenerator = new FsVerityGenerator();
            fsVerityGenerator.setCsOffset(offset);
            fsVerityGenerator.generateFsVerityDigest(inputStream, fileSize, flags);

            byte[] signature;
            if (!selfSign) {
                // Normal mode: generate signature with ownerID from certificate
                String ownerID = getOwnerIdFromCert();
                byte[] fsVerityDigest = fsVerityGenerator.getFsVerityDigest();
                signature = generateSignature(fsVerityDigest, ownerID);
                LOGGER.info("Generated PKCS7 signature, size: {} bytes", signature.length);
            } else {
                // Self-sign mode: use descriptorDigest as signature
                signature = fsVerityGenerator.getDescriptorDigest();
                LOGGER.info("Self-sign mode: using descriptor digest as signature, size: {} bytes", signature.length);
            }

            // Build FsVerityDescriptor
            FsVerityDescriptor.Builder fsdbuilder = new FsVerityDescriptor.Builder().setFileSize(fileSize)
                .setHashAlgorithm(FsVerityGenerator.getFsVerityHashAlgorithm())
                .setLog2BlockSize(FsVerityGenerator.getLog2BlockSize())
                .setSaltSize((byte) fsVerityGenerator.getSaltSize())
                .setSignSize(signature.length)
                .setSalt(fsVerityGenerator.getSalt())
                .setRawRootHash(fsVerityGenerator.getRootHash())
                .setFlags(flags)
                .setCsVersion(ELF_CODE_SIGN_VERSION);

            FsVerityDescriptorWithSign fsVerityDescriptorWithSign = new FsVerityDescriptorWithSign(fsdbuilder.build(),
                signature);

            // Convert to byte array (C++ uses ToByteArray)
            // Return FsVerityDescriptorWithSign directly, NOT ElfSignBlock
            // The merkle tree is NOT included in the ELF code sign block
            byte[] codeSignData = fsVerityDescriptorWithSign.toByteArray();

            LOGGER.info("Sign elf successfully, code sign block size: {} bytes", codeSignData.length);
            return codeSignData;
        }
    }

    /**
     * Get owner ID from certificate (organizationalUnitName)
     * - Checks cert chain size >= MIN_CERT_CHAIN_SIZE
     * - Extracts OU field from first certificate's subject
     *
     * @return owner ID from certificate
     * @throws CodeSignException if certificate is invalid
     */
    private String getOwnerIdFromCert() throws CodeSignException {
        if (signConfig == null || signConfig.getSigner() == null) {
            return "";
        }
        byte[] preSignedData = new BcSignedDataGenerator().generateSignedData(new byte[100], signConfig);
        List<java.security.cert.X509Certificate> certificates = signConfig.getCertificates();
        if (certificates == null || certificates.isEmpty()) {
            throw new CodeSignException("No certificates configured for sign");
        }

        // Check cert chain size
        if (certificates.size() < MIN_CERT_CHAIN_SIZE) {
            throw new CodeSignException("sign certs not a cert chain");
        }

        // Get owner ID from first certificate's organizationalUnitName (OU)
        java.security.cert.X509Certificate cert = certificates.get(0);
        String ownerID = "";

        // Parse X500Name and extract OU field, following getCertificateCN pattern
        String nameStr = cert.getSubjectX500Principal().getName();
        X500Name name = new X500Name(nameStr);
        RDN[] organizationalUnits = name.getRDNs(BCStyle.OU);
        if (organizationalUnits.length > 0) {
            ownerID = organizationalUnits[0].getFirst().getValue().toString();
        }

        LOGGER.info("Got ownerID from certificate: {}", ownerID);
        return ownerID;
    }

    private byte[] generateSignature(byte[] signedData, String ownerID) throws CodeSignException {
        SignerConfig copiedConfig = signConfig;
        // signConfig is created by SignerFactory
        if ((copiedConfig.getSigner() instanceof LocalSigner)) {
            if (copiedConfig.getCertificates().isEmpty()) {
                throw new CodeSignException(
                    CodeSignErrMsg.CERTIFICATES_CONFIGURE_ERROR.toString("No certificate is configured for sign"));
            }
            BcSignedDataGenerator bcSignedDataGenerator = new BcSignedDataGenerator();
            bcSignedDataGenerator.setOwnerID(ownerID);
            return bcSignedDataGenerator.generateSignedData(signedData, copiedConfig);
        } else {
            copiedConfig = signConfig.copy();
            BcSignedDataGenerator bcSignedDataGenerator = new BcSignedDataGenerator();
            bcSignedDataGenerator.setOwnerID(ownerID);
            return bcSignedDataGenerator.generateSignedData(signedData, copiedConfig);
        }
    }
}
