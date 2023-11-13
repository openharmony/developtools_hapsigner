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

package com.ohos.hapsigntool.hap.sign;

import com.ohos.hapsigntool.codesigning.exception.CodeSignException;
import com.ohos.hapsigntool.codesigning.exception.FsVerityDigestException;
import com.ohos.hapsigntool.codesigning.sign.CodeSigning;
import com.ohos.hapsigntool.hap.config.SignerConfig;
import com.ohos.hapsigntool.hap.entity.HwBlockHead;
import com.ohos.hapsigntool.hap.entity.HwSignHead;
import com.ohos.hapsigntool.hap.entity.SignBlockData;
import com.ohos.hapsigntool.hap.entity.SignatureBlockTags;
import com.ohos.hapsigntool.hap.entity.SignatureBlockTypes;
import com.ohos.hapsigntool.hap.exception.HapFormatException;
import com.ohos.hapsigntool.hap.exception.ProfileException;
import com.ohos.hapsigntool.utils.FileUtils;
import com.ohos.hapsigntool.utils.ParamConstants;
import com.ohos.hapsigntool.utils.ParamProcessUtil;
import com.ohos.hapsigntool.utils.StringUtils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * LiteOS bin file Signature signer.
 *
 * @since 2021/12/21
 */
public class SignElf {
    private static final Logger LOGGER = LogManager.getLogger(SignElf.class);

    private static final String CODESIGN_OFF = "0";

    private static final char CODESIGN_BLOCK_TYPE = 3;

    private static int blockNum = 0;

    /**
     * Constructor of Method
     */
    private SignElf() {
    }

    /**
     * Sign the bin file.
     *
     * @param signerConfig Config of the bin file to be signed.
     * @param signParams The input parameters of sign bin.
     * @return true if sign successfully; false otherwise.
     */
    public static boolean sign(SignerConfig signerConfig, Map<String, String> signParams) {
        boolean isSuccess = false;
        /* 1. Make block head, write to output file. */
        String inputFile = signParams.get(ParamConstants.PARAM_BASIC_INPUT_FILE);
        String outputFile = signParams.get(ParamConstants.PARAM_BASIC_OUTPUT_FILE);
        String profileSigned = signParams.get(ParamConstants.PARAM_BASIC_PROFILE_SIGNED);
        if (!writeBlockDataToFile(signerConfig, inputFile, outputFile, profileSigned, signParams)) {
            LOGGER.error("The block head data made failed.");
            ParamProcessUtil.delDir(new File(outputFile));
            return false;
        }
        LOGGER.info("The block head data made success.");

        /* 2. Make sign data, and write to output file */
        if (!writeSignHeadDataToOutputFile(inputFile, outputFile, blockNum)) {
            LOGGER.error("The sign head data made failed.");
            ParamProcessUtil.delDir(new File(outputFile));
        } else {
            isSuccess = true;
        }
        return isSuccess;
    }

    private static boolean writeBlockDataToFile(SignerConfig signerConfig,
        String inputFile, String outputFile, String profileSigned, Map<String, String> signParams) {
        try {
            String profileFile = signParams.get(ParamConstants.PARAM_BASIC_PROFILE);

            List<SignBlockData> signDataList = new ArrayList<>();

            long binFileLen = FileUtils.getFileLen(inputFile);
            if (binFileLen == -1) {
                LOGGER.error("file length is invalid, bin file len: " + binFileLen);
                throw new IOException();
            }
            // 1. generate sign data
            if (!StringUtils.isEmpty(signParams.get(ParamConstants.PARAM_BASIC_PROFILE))) {
                signDataList.add(generateProfileSignByte(profileFile, profileSigned));
            }
            blockNum = signDataList.size();
            SignBlockData codeSign = generateCodeSignByte(signerConfig, signParams, inputFile, blockNum, binFileLen);
            if (codeSign != null) {
                signDataList.add(0, codeSign);
            }
            blockNum = signDataList.size();
            // 2. use sign data generate offset and sign block head
            generateSignBlockHead(signDataList);

            return writeSignedElf(inputFile, signDataList, outputFile);
        } catch (IOException e) {
            LOGGER.error("writeBlockDataToFile failed.", e);
            return false;
        } catch (FsVerityDigestException | CodeSignException | HapFormatException | ProfileException e) {
            LOGGER.error("codesign failed.", e);
            return false;
        }
    }

    private static boolean writeSignedElf(String inputFile, List<SignBlockData> signBlockList, String outputFile) {
        try (FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
             DataOutputStream dataOutputStream = new DataOutputStream(fileOutputStream)) {
            // 1. write the input file to the output file.
            if (!FileUtils.writeFileToDos(inputFile, dataOutputStream)) {
                LOGGER.error("Failed to write information of input file: " + inputFile
                        + " to outputFile: " + outputFile);
                throw new IOException();
            }

            // 2. write block head to the output file.
            for (SignBlockData signBlockData : signBlockList) {
                if (!FileUtils.writeByteToDos(signBlockData.getBlockHead(), dataOutputStream)) {
                    LOGGER.error("Failed to write Block Head to output file: " + outputFile);
                    throw new IOException();
                }
            }

            // 3. write block data to the output file.
            for (SignBlockData signBlockData : signBlockList) {
                boolean isSuccess;
                if (signBlockData.isByte()) {
                    isSuccess = FileUtils.writeByteToDos(signBlockData.getSignData(), dataOutputStream);
                } else {
                    isSuccess = FileUtils.writeFileToDos(signBlockData.getSignFile(), dataOutputStream);
                }

                if (!isSuccess) {
                    LOGGER.error("Failed to write Block Data to output file: " + outputFile);
                    throw new IOException();
                }
            }
        } catch (IOException e) {
            LOGGER.error("writeSignedBin failed.", e);
            return false;
        }
        return true;
    }

    private static void generateSignBlockHead(List<SignBlockData> signDataList)
            throws IOException {
        long offset = (long) HwBlockHead.getElfBlockLen() * signDataList.size();

        for (int i = 0; i < signDataList.size(); i++) {
            SignBlockData signBlockData = signDataList.get(i);

            signBlockData.setBlockHead(HwBlockHead.getBlockHeadLittleEndian(signBlockData.getType(),
                    SignatureBlockTags.DEFAULT, (int) signBlockData.getLen(), (int) offset));
            offset += signBlockData.getLen();
            if (isLongOverflowInteger(offset)) {
                LOGGER.error("The sign block " + i + "offset is overflow integer, offset: " + offset);
                throw new IOException();
            }
        }
    }

    private static SignBlockData generateProfileSignByte(String profileFile, String profileSigned) throws IOException {
        long profileDataLen = FileUtils.getFileLen(profileFile);

        if (profileDataLen == -1 || isLongOverflowShort(profileDataLen)) {
            LOGGER.error("file length is invalid, profileDataLen: " + profileDataLen);
            throw new IOException();
        }

        char isSigned = SignatureBlockTypes.getProfileBlockTypes(profileSigned);
        return new SignBlockData(profileFile, isSigned);
    }

    private static SignBlockData generateCodeSignByte(SignerConfig signerConfig, Map<String, String> signParams,
        String inputFile, int blockNum, long binFileLen) throws IOException,
            FsVerityDigestException, CodeSignException, HapFormatException, ProfileException {
        if (CODESIGN_OFF.equals(signParams.get(ParamConstants.PARAM_SIGN_CODE))) {
            return null;
        }
        CodeSigning codeSigning = new CodeSigning(signerConfig);
        long offset = binFileLen + (long) HwBlockHead.getElfBlockLen() * blockNum;
        String profileContent = signParams.get(ParamConstants.PARAM_PROFILE_JSON_CONTENT);
        byte[] codesignData = codeSigning.getCodeSignBlock(new File(inputFile), offset,
                signParams.get(ParamConstants.PARAM_IN_FORM), profileContent);
        return new SignBlockData(codesignData, CODESIGN_BLOCK_TYPE);
    }

    private static boolean writeSignHeadDataToOutputFile(String inputFile, String outputFile, int blockNum) {
        long size = FileUtils.getFileLen(outputFile) - FileUtils.getFileLen(inputFile);
        if (isLongOverflowInteger(size)) {
            LOGGER.error("File size is Overflow integer range.");
            return false;
        }
        HwSignHead signHeadData = new HwSignHead();
        byte[] signHeadByte = signHeadData.getSignHeadLittleEndian((int) size, blockNum);
        if (signHeadByte == null) {
            LOGGER.error("Failed to get sign head data.");
            return false;
        }
        return FileUtils.writeByteToOutFile(signHeadByte, outputFile);
    }

    private static boolean isLongOverflowInteger(long num) {
        return (num - (num & 0xffffffffL)) != 0;
    }

    private static boolean isLongOverflowShort(long num) {
        return (num - (num & 0xffffL)) != 0;
    }
}
