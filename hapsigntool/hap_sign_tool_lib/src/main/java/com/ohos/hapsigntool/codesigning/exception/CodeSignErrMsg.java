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
    public static ErrorMsg FILE_FORMAT_UNSUPPORTED_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("10")
        .addErrCode("001")
        .addDescription("File Read Error")
        .addCause("Code sign does not support the file format")
        .addSolution("code sign supports {%s} format")
        .build();

    public static ErrorMsg FILE_4K_ALIGNMENT_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("10")
        .addErrCode("002")
        .addDescription("File Read Error")
        .addCause("Invalid data size {%d}, not a multiple of 4096")
        .build();

    public static ErrorMsg HNP_FILE_DESCRIPTION_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("10")
        .addErrCode("003")
        .addDescription("File Read Error")
        .addCause("Hnp {%s} is not described in module.json")
        .addSolution("Hnp should be described in module.json")
        .build();

    public static ErrorMsg EXTRACT_HNP_FILE_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("10")
        .addErrCode("004")
        .addDescription("File Read Error")
        .addCause("Extract hnp file {%s} error")
        .addSolution("Check whether the hnp file is packaged correctly")
        .build();

    public static ErrorMsg READ_INPUT_STREAM_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("10")
        .addErrCode("005")
        .addDescription("File Read Error")
        .addCause("read buffer from input error")
        .build();

    public static ErrorMsg CERTIFICATES_CONFIGURE_EMPTY_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("11")
        .addErrCode("001")
        .addDescription("Certificates Error")
        .addCause("No certificates configured for sign")
        .addSolution("Please check whether the certificate is correct")
        .build();

    public static ErrorMsg PROFILE_TYPE_UNSUPPORTED_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("12")
        .addErrCode("001")
        .addDescription("Profile Content Error")
        .addCause("Unsupported profile type")
        .addSolution("Profile type should be debug or release")
        .build();

    public static ErrorMsg PROFILE_TYPE_NOT_EXISTED_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("12")
        .addErrCode("002")
        .addDescription("Profile Content Error")
        .addCause("Key named 'type' does not exist in profile")
        .build();

    public static ErrorMsg PROFILE_BUNDLE_INFO_NOT_EXISTED_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("12")
        .addErrCode("003")
        .addDescription("Profile Content Error")
        .addCause("Key named 'bundle-info' does not exist in profile")
        .build();

    public static ErrorMsg PROFILE_APPID_VALUE_TYPE_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("12")
        .addErrCode("004")
        .addDescription("Profile Content Error")
        .addCause("Value of app-identifier is not string")
        .addSolution("app-identifier should be string")
        .build();

    public static ErrorMsg PROFILE_APPID_VALUE_LENGTH_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("12")
        .addErrCode("005")
        .addDescription("Profile Content Error")
        .addCause("Value length of app-identifier is invalid")
        .build();

    public static ErrorMsg PROFILE_JSON_PARSE_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("12")
        .addErrCode("006")
        .addDescription("Profile Content Error")
        .addCause("Profile json content is invalid")
        .addSolution("Please check whether the profile json is correct")
        .build();

    public static ErrorMsg MODULE_JSON_PARSE_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("13")
        .addErrCode("001")
        .addDescription("Module Content Error")
        .addCause("Module json content is invalid")
        .addSolution("Please check whether the module json is correct")
        .build();

    public static ErrorMsg DIGEST_ALGORITHM_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("14")
        .addErrCode("001")
        .addDescription("Digest Algorithm Error")
        .addCause("Invalid algorithm {%s}")
        .build();

    public static ErrorMsg SIGN_SIZE_ZERO_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("001")
        .addDescription("Code Sign Error")
        .addCause("The file size in bundle is 0")
        .build();

    public static ErrorMsg SIGN_SIZE_OVER_LIMIT_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("15")
        .addErrCode("002")
        .addDescription("Code Sign Error")
        .addCause("The file size in bundle is over limit")
        .build();

    public static ErrorMsg ELF_FILE_HEADER_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("16")
        .addErrCode("001")
        .addDescription("Elf File Error")
        .addCause("ELF header is incorrect")
        .addSolution("Failed to parse the elf file, please check whether the file header information is correct")
        .build();

    public static ErrorMsg ELF_PROGRAM_HEADER_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("16")
        .addErrCode("002")
        .addDescription("Elf File Error")
        .addCause("ELF program header is incorrect")
        .addSolution("Failed to parse the elf file, please check whether the file header information is correct")
        .build();

    public static ErrorMsg ELF_EI_CLASS_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("16")
        .addErrCode("003")
        .addDescription("Elf File Error")
        .addCause("ELF ei_class is incorrect")
        .addSolution("Failed to parse the elf file, please check whether the file header information is correct")
        .build();

    public static ErrorMsg ELF_EI_DATA_ERROR = ErrorMsg.getCodeSignErrBuilder()
        .addTypeCode("16")
        .addErrCode("004")
        .addDescription("Elf File Error")
        .addCause("ELF ei_data is incorrect")
        .addSolution("Failed to parse the elf file, please check whether the file header information is correct")
        .build();
}
