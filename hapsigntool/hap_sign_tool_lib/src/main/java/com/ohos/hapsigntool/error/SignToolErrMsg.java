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

package com.ohos.hapsigntool.error;

/**
 * SignToolErrMsg
 *
 * @since 2025/01/06
 */
public class SignToolErrMsg {
    // unknown error
    public static ErrorMsg UNKNOWN_ERROR = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("10")
            .addErrCode("001")
            .addDescription("%s")
            .build();

    // command error
    public static ErrorMsg UNSUPPORTED_METHOD = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("11")
            .addErrCode("001")
            .addDescription("Unsupported command method")
            .addCause("Can not find method {%s}")
            .addSolution("Please check input the first param")
            .build();

    public static ErrorMsg PARAM_CHECK_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("11")
            .addErrCode("002")
            .addDescription("{%s} param is incorrect")
            .addCause("%s")
            .build();

    public static ErrorMsg PARAM_NUM_ERROR = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("11")
            .addErrCode("003")
            .addDescription("Check param num failed")
            .addCause("Please input at least two params")
            .build();

    public static ErrorMsg PARAM_VALUE_EMPTY = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("11")
            .addErrCode("004")
            .addDescription("Check param num failed")
            .addCause("Param {%s} value could not be empty")
            .build();

    public static ErrorMsg PARAM_NOT_TRUSTED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("11")
            .addErrCode("005")
            .addDescription("Param is not trusted")
            .addCause("Param {%s} value is not trusted")
            .build();

    public static ErrorMsg PARAM_NOT_IN_PAIRS = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("11")
            .addErrCode("006")
            .addDescription("Param {-key value} must in pairs")
            .addCause("Check param {%s} failed")
            .build();

    public static ErrorMsg PARAM_DUPLICATE = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("11")
            .addErrCode("007")
            .addDescription("Check param num failed")
            .addCause("Param {%s} is duplicated")
            .build();

    public static ErrorMsg PARAM_REQUIRED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("11")
            .addErrCode("008")
            .addDescription("Check param failed")
            .addCause("Param {%s} is required, but can not be found")
            .addSolution("Please input required param")
            .build();

    public static ErrorMsg MISSING_PARAM = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("11")
            .addErrCode("008")
            .addDescription("Check param failed")
            .addCause("Missed param {%s}")
            .build();

    // file error
    public static ErrorMsg LOAD_REMOTE_PLUGIN_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("12")
            .addErrCode("001")
            .addDescription("Load remote sign plugin failed")
            .addCause("%s")
            .build();

    public static ErrorMsg FILE_NOT_EXIST = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("12")
            .addErrCode("002")
            .addDescription("Param {%s} is not exist")
            .build();

    public static ErrorMsg FILE_WRITE_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("12")
            .addErrCode("003")
            .addDescription("Write file failed")
            .addCause("%s")
            .build();

    public static ErrorMsg FILE_READ_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("12")
            .addErrCode("004")
            .addDescription("Read file {%s} failed")
            .build();

    public static ErrorMsg NOT_SUPPORT_FILE = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("12")
            .addErrCode("005")
            .addDescription("Not support file: %s")
            .build();

    // cert error
    public static ErrorMsg CERT_DN_FORMAT_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("13")
            .addErrCode("001")
            .addDescription("Check DN format failed")
            .addCause("Format error, must be \"X=xx,XX=xxx,...\"")
            .addSolution("Please check param {%s}")
            .build();

    public static ErrorMsg CERT_FORMAT_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("13")
            .addErrCode("002")
            .addDescription("Certificate format is in correct, please check your appCertFile parameter.")
            .addCause("Exception message: %s")
            .addSolution("{-appCertFile} should input a file ending in .cer")
            .build();

    public static ErrorMsg GENERATE_CA_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("13")
            .addErrCode("003")
            .addDescription("Parameter '%s' and parameter '%s' are inconsistent")
            .build();

    public static ErrorMsg CERT_CHAIN_FORMAT_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("13")
            .addErrCode("004")
            .addDescription("Profile cert must a cert chain")
            .addCause("cause in cert file: %s")
            .build();

    public static ErrorMsg NO_SUCH_SIGNATURE = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("13")
            .addErrCode("005")
            .addDescription("No such algorithm")
            .addCause("Exception message: %s")
            .build();

    public static ErrorMsg CERT_IO_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("13")
            .addErrCode("006")
            .addDescription("Certificate IO failed")
            .addCause("Exception message: %s")
            .build();

    public static ErrorMsg CERTIFICATE_ERROR = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("13")
            .addErrCode("007")
            .addDescription("Certificate check failed")
            .addCause("Exception message: %s")
            .build();

    public static ErrorMsg IO_CSR_ERROR = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("13")
            .addErrCode("008")
            .addDescription("generate csr failed")
            .addCause("Exception message: %s")
            .build();

    // key store error
    public static ErrorMsg KEY_ALIAS_NOT_FOUND = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("14")
            .addErrCode("001")
            .addDescription("KeyAlias {%s} is not exist in {%s}")
            .addSolution("Please check keystore file and keyAlias, ensure keyAlias is exist")
            .addSolution("Use jdk tool [keytool] check keystore: [keytool -list -keystore xxx.p12]")
            .build();

    public static ErrorMsg KEY_ALIAS_EXIST = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("14")
            .addErrCode("002")
            .addDescription("KeyAlias {%s} is exist in {%s}, cloud not overwrite.")
            .addSolution("Please check keystore file and keyAlias, ensure keyAlias is not exist")
            .addSolution("Use jdk tool [keytool] check keystore: [keytool -list -keystore xxx.p12]")
            .build();

    public static ErrorMsg INIT_KEYSTORE_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("14")
            .addErrCode("003")
            .addDescription("Init keystore failed: ")
            .addCause("Exception message: %s")
            .addSolution("The key store file does not exist, please check the key store file path.")
            .addSolution("Incorrect keystore password, please input the correct plaintext password.")
            .addSolution("The keystore was created by a newer JDK version, please use the same JDK version")
            .build();

    public static ErrorMsg INVALID_KEY = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("14")
            .addErrCode("004")
            .addDescription("Invalid Key")
            .addCause("Exception message: %s")
            .build();

    public static ErrorMsg ALGORITHM_NOT_SUPPORT = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("14")
            .addErrCode("005")
            .addDescription("Not support algorithm")
            .addCause("Exception message: %s")
            .build();

    public static ErrorMsg KEYSTORE_ERROR = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("14")
            .addErrCode("006")
            .addDescription("Keystore exception")
            .addCause("Exception message: %s")
            .build();

    public static ErrorMsg KEY_PASSWORD_ERROR = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("14")
            .addErrCode("007")
            .addDescription("Key alias {%s} password error")
            .addCause("Exception message: %s")
            .build();

    public static ErrorMsg NO_USABLE_CERT = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("14")
            .addErrCode("008")
            .addDescription("No usable cert found in {%s}")
            .addCause("MayBe the certificate in keystore is invalid.")
            .build();

    // signature error
    public static ErrorMsg SIGNATURE_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("15")
            .addErrCode("001")
            .addDescription("Signature failed")
            .addCause("Exception message: %s")
            .build();

    public static ErrorMsg SIGNATURE_NOT_MATCHED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("15")
            .addErrCode("002")
            .addDescription("Signature not matched!")
            .addSolution("Please check if the keyAlias private key matches the public key in the certificate")
            .addSolution("If the certificate is changed, the keyAlias should be replaced synchronously")
            .build();

    public static ErrorMsg VERIFY_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("15")
            .addErrCode("003")
            .addDescription("Verify signature failed")
            .addCause("Exception message: %s")
            .build();

    // profile error
    public static ErrorMsg VERIFY_PROFILE_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("16")
            .addErrCode("001")
            .addDescription("Verify profile failed")
            .addCause("Exception message: %s")
            .build();

    // zip error
    public static ErrorMsg READ_ZIP_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("17")
            .addErrCode("001")
            .addDescription("Read zip file failed")
            .addCause("Exception message: %s")
            .addSolution("App (or hap/hsp/hnp) use zip format.")
            .addSolution("Zip file can support a maximum size of 4G and 65535 sub files.")
            .addSolution("If this value is exceeded, it will be automatically converted to zip64.")
            .addSolution("Please check if file is zip64 format, or zip formatted correctly.")
            .build();

    public static ErrorMsg WRITE_ZIP_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("17")
            .addErrCode("002")
            .addDescription("Write zip file failed")
            .addCause("Exception message: %s")
            .build();

    public static ErrorMsg ALIGNMENT_ZIP_FAILED = ErrorMsg.getSignToolErrBuilder()
            .addTypeCode("17")
            .addErrCode("003")
            .addDescription("Alignment zip file failed")
            .addCause("Exception message: %s")
            .build();
}
