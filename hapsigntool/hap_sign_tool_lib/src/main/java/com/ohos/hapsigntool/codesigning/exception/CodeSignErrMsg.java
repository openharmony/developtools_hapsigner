/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.codesigning.exception;

import com.ohos.hapsigntool.error.ErrorMsg;

/**
 * CodeSignErrMsg
 *
 * @since 2025/01/06
 */
public class CodeSignErrMsg {
    /**
     * FILE_FORMAT_UNSUPPORTED_ERROR
     */
    public static final ErrorMsg FILE_FORMAT_UNSUPPORTED_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("10")
        .addErrCode("001")
        .addDescription("File Read Error")
        .addCause("Code sign does not support the file format")
        .addSolution("Code sign supports {%s} format")
        .build();

    /**
     * FILE_4K_ALIGNMENT_ERROR
     */
    public static final ErrorMsg FILE_4K_ALIGNMENT_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("10")
        .addErrCode("002")
        .addDescription("File Read Error")
        .addCause("Invalid data size {%d}, not a multiple of 4096")
        .build();

    /**
     * HNP_FILE_DESCRIPTION_ERROR
     */
    public static final ErrorMsg HNP_FILE_DESCRIPTION_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("10")
        .addErrCode("003")
        .addDescription("File Read Error")
        .addCause("Hnp {%s} is not described in module.json")
        .addSolution("Hnp should be described in module.json")
        .build();

    /**
     * EXTRACT_HNP_FILE_ERROR
     */
    public static final ErrorMsg EXTRACT_HNP_FILE_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("10")
        .addErrCode("004")
        .addDescription("File Read Error")
        .addCause("Extract hnp file {%s} error")
        .addSolution("Check whether the hnp file is packaged correctly")
        .build();

    /**
     * READ_INPUT_STREAM_ERROR
     */
    public static final ErrorMsg READ_INPUT_STREAM_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("10")
        .addErrCode("005")
        .addDescription("File Read Error")
        .addCause("Read buffer from input error")
        .build();

    /**
     * CERTIFICATES_CONFIGURE_EMPTY_ERROR
     */
    public static final ErrorMsg CERTIFICATES_CONFIGURE_EMPTY_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("11")
        .addErrCode("001")
        .addDescription("Certificates Error")
        .addCause("No certificates configured for sign")
        .addSolution("Please check whether the certificate is correct")
        .build();

    /**
     * PROFILE_TYPE_UNSUPPORTED_ERROR
     */
    public static final ErrorMsg PROFILE_TYPE_UNSUPPORTED_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("12")
        .addErrCode("001")
        .addDescription("Profile Content Error")
        .addCause("Unsupported profile type")
        .addSolution("Profile type should be debug or release")
        .build();

    /**
     * PROFILE_TYPE_NOT_EXISTED_ERROR
     */
    public static final ErrorMsg PROFILE_TYPE_NOT_EXISTED_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("12")
        .addErrCode("002")
        .addDescription("Profile Content Error")
        .addCause("Key named 'type' does not exist in profile")
        .build();

    /**
     * PROFILE_BUNDLE_INFO_NOT_EXISTED_ERROR
     */
    public static final ErrorMsg PROFILE_BUNDLE_INFO_NOT_EXISTED_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("12")
        .addErrCode("003")
        .addDescription("Profile Content Error")
        .addCause("Key named 'bundle-info' does not exist in profile")
        .build();

    /**
     * PROFILE_APPID_VALUE_TYPE_ERROR
     */
    public static final ErrorMsg PROFILE_APPID_VALUE_TYPE_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("12")
        .addErrCode("004")
        .addDescription("Profile Content Error")
        .addCause("Value type of app-identifier is not string")
        .addSolution("Value type of app-identifier should be string")
        .build();

    /**
     * PROFILE_APPID_VALUE_LENGTH_ERROR
     */
    public static final ErrorMsg PROFILE_APPID_VALUE_LENGTH_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("12")
        .addErrCode("005")
        .addDescription("Profile Content Error")
        .addCause("Value length of app-identifier is invalid")
        .build();

    /**
     * PROFILE_JSON_PARSE_ERROR
     */
    public static final ErrorMsg PROFILE_JSON_PARSE_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("12")
        .addErrCode("006")
        .addDescription("Profile Content Error")
        .addCause("Profile json content is invalid")
        .addSolution("Please check whether the profile json is correct")
        .build();

    /**
     * MODULE_JSON_PARSE_ERROR
     */
    public static final ErrorMsg MODULE_JSON_PARSE_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("13")
        .addErrCode("001")
        .addDescription("Module Content Error")
        .addCause("Module json content is invalid")
        .addSolution("Please check whether the module json is correct")
        .build();

    /**
     * DIGEST_ALGORITHM_ERROR
     */
    public static final ErrorMsg DIGEST_ALGORITHM_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("14")
        .addErrCode("001")
        .addDescription("Digest Algorithm Error")
        .addCause("Invalid algorithm {%s}")
        .build();

    /**
     * SIGN_SIZE_ZERO_ERROR
     */
    public static final ErrorMsg SIGN_SIZE_ZERO_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("001")
        .addDescription("Code Sign Error")
        .addCause("The file size in bundle is 0")
        .build();

    /**
     * SIGN_SIZE_OVER_LIMIT_ERROR
     */
    public static final ErrorMsg SIGN_SIZE_OVER_LIMIT_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("002")
        .addDescription("Code Sign Error")
        .addCause("The file size in bundle is over limit")
        .build();

    /**
     * SALT_SIZE_LENGTH_ERROR
     */
    public static final ErrorMsg SALT_SIZE_LENGTH_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("003")
        .addDescription("Code Sign Error")
        .addCause("Salt is too long")
        .build();

    /**
     * SIGN_LIBS_ERROR
     */
    public static final ErrorMsg SIGN_LIBS_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("004")
        .addDescription("Code Sign Error")
        .addCause("Sign libs error")
        .build();

    /**
     * SIGN_HNP_ERROR
     */
    public static final ErrorMsg SIGN_HNP_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("005")
        .addDescription("Code Sign Error")
        .addCause("Sign hnp error")
        .build();

    /**
     * ENCODE_DATA_ERROR
     */
    public static final ErrorMsg ENCODE_DATA_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("006")
        .addDescription("Code Sign Error")
        .addCause("Encode data error")
        .build();

    /**
     * CERTIFICATE_ENCODING_ERROR
     */
    public static final ErrorMsg CERTIFICATE_ENCODING_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("007")
        .addDescription("Code Sign Error")
        .addCause("Create sign info failed")
        .build();

    /**
     * CREATE_CRL_ERROR
     */
    public static final ErrorMsg CREATE_CRL_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("008")
        .addDescription("Code Sign Error")
        .addCause("Create crl failed")
        .build();

    /**
     * SIGNER_SIGN_ERROR
     */
    public static final ErrorMsg SIGNER_SIGN_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("009")
        .addDescription("Code Sign Error")
        .addCause("Signer sign data failed")
        .build();

    /**
     * SIGN_CONTENT_EMPTY_ERROR
     */
    public static final ErrorMsg SIGN_CONTENT_EMPTY_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("010")
        .addDescription("Code Sign Error")
        .addCause("The content to be signed is empty")
        .build();

    /**
     * VERIFY_SIGNATURE_FROM_SERVER_ERROR
     */
    public static final ErrorMsg VERIFY_SIGNATURE_FROM_SERVER_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("011")
        .addDescription("Code Sign Error")
        .addCause("Verify signature from server failed")
        .build();

    /**
     * SIGNATURE_VERIFY_FAILED_ERROR
     */
    public static final ErrorMsg SIGNATURE_VERIFY_FAILED_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("011")
        .addDescription("Code Sign Error")
        .addCause("Signature verify failed")
        .build();

    /**
     * ELF_FILE_HEADER_ERROR
     */
    public static final ErrorMsg ELF_FILE_HEADER_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("16")
        .addErrCode("001")
        .addDescription("Elf File Error")
        .addCause("ELF header is incorrect")
        .addSolution("Failed to parse the elf file, please check whether the file header information is correct")
        .build();

    /**
     * ELF_PROGRAM_HEADER_ERROR
     */
    public static final ErrorMsg ELF_PROGRAM_HEADER_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("16")
        .addErrCode("002")
        .addDescription("Elf File Error")
        .addCause("ELF program header is incorrect")
        .addSolution("Failed to parse the elf file, please check whether the file header information is correct")
        .build();

    /**
     * ELF_EI_CLASS_ERROR
     */
    public static final ErrorMsg ELF_EI_CLASS_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("16")
        .addErrCode("003")
        .addDescription("Elf File Error")
        .addCause("ELF ei_class is incorrect")
        .addSolution("Failed to parse the elf file, please check whether the file header information is correct")
        .build();

    /**
     * ELF_EI_DATA_ERROR
     */
    public static final ErrorMsg ELF_EI_DATA_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("16")
        .addErrCode("004")
        .addDescription("Elf File Error")
        .addCause("ELF ei_data is incorrect")
        .addSolution("Failed to parse the elf file, please check whether the file header information is correct")
        .build();

}
