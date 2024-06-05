/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
#ifndef OHOS_INDUSTRIAL_BUS_ERRNO_H
#define OHOS_INDUSTRIAL_BUS_ERRNO_H
namespace OHOS {
    namespace SignatureTools {
        const int  RET_OK = 0;
        const int  RET_FAILED = -1;
        const int  RET_PASS_ERROR = -2;
		
        const int COMMAND_ERROR = -101;
        /**
         * Enum constant FILE_NOT_FOUND.
         */
        const int FILE_NOT_FOUND = -102;
        /**
         * Enum constant WRITE_FILE_ERROR.
         */
        const int WRITE_FILE_ERROR = -103;
        /**
         * Enum constant READ_FILE_ERROR.
         */
        const int READ_FILE_ERROR = -104;
        /**
         * Enum constant NOT_SUPPORT_ERROR.
         */
        const int NOT_SUPPORT_ERROR = -105;
        /**
         * Enum constant NETWORK_ERROR.
         */
        const int NETWORK_ERROR = -106;
        /**
         * Enum constant SIGN_ERROR.
         */
        const int SIGN_ERROR = -107;
        /**
         * Enum constant VERIFY_ERROR.
         */
        const int VERIFY_ERROR = -108;
        /**
         * Enum constant ACCESS_ERROR.
         */
        const int ACCESS_ERROR = -109;
        /**
         * Enum constant COMMAND_PARAM_ERROR.
         */
        const int COMMAND_PARAM_ERROR = -110;
        /**
         * Enum constant OPERATOR_CREATION_ERROR.
         */
        const int OPERATOR_CREATION_ERROR = -111;
        /**
         * Enum constant PARAM_NOT_EXIST_ERROR.
         */
        const int PARAM_NOT_EXIST_ERROR = -113;
        /**
         * Enum constant KEYSTORE_OPERATION_ERROR.
         */
        const int KEYSTORE_OPERATION_ERROR = -114;
        /**
         * Enum constant CERTIFICATE_ERROR.
         */
        const int CERTIFICATE_ERROR = -115;
        /**
         * Enum constant KEY_ERROR.
         */
        const int KEY_ERROR = -116;
        /**
         * Enum constant IO_CERT_ERROR.
         */
        const int IO_CERT_ERROR = -117;
        /**
         * Enum constant IO_CSR_ERROR.
         */
        const int IO_CSR_ERROR = -118;
        /**
         * Enum constant ZIP_ERROR.
         */
        const int ZIP_ERROR = -119;
        /**
         * Enum constant FORMAT_ERROR.
         */
        const int FORMAT_ERROR = -120;
        /**
         * Enum constant INIT_ERROR.
         */
        const int INIT_ERROR = -121;
        /**
         * Enum constant INVALID_ERROR.
         */
        const int INVALIDPARAM_ERROR = -122;
        /**
         * Enum constant INVALIDSIGNTIME_ERROR.
         */
        const int INVALIDSIGNTIME_ERROR = -123;
        /**
         * Enum constant PKCS7_FINAL_ERROR
         */
        const int PKCS7_FINAL_ERROR = -124;
        /**
         * Enum constant PARSE_ERROR
         */
        const int PARSE_ERROR = -125;
        /**
         * Enum constant PKCS7_ADD_ATTRIBUTE_ERROR
         */
        const int PKCS7_ADD_ATTRIBUTE_ERROR = -126;
        /**
         * Enum constant MEMORY_ALLOC_ERROR
         */
        const int MEMORY_ALLOC_ERROR = -127;
        /**
         * Enum constant PKCS7_SIGN_ERROR
         */
        const int PKCS7_SIGN_ERROR = -128;
        /**
         * Enum constant CREATE_NID_ERROR
         */
        const int CREATE_NID_ERROR = -129;
        /**
        * Enum constant GENERATEPKCS7_ERROR
        */
        const int GENERATEPKCS7_ERROR = -130;
                /**
        * Enum constant CHCKE_PROFILE_ERROR
        */
        const int CHCKE_PROFILE_ERROR = -131;
        /**
        * Enum constant PKCS7_PARSE_ERROR
        */
        const int PKCS7_PARSE_ERROR = -132;
        /**
        * Enum constant PKCS7_VERIFY_ERROR
        */
        const int PKCS7_VERIFY_ERROR = -133;
        /**
        * Enum constant NO_CONTENT_ERROR
        */
        const int NO_CONTENT_ERROR = -134;
        /**
        * Enum constant NO_CONTENT_ERROR
        */
        const int PARSE_PROVISION_ERROR = -135;
        /**
        * Enum constant MATCH_ERROR
        */
        const int MATCH_ERROR = -136;

        /**
        * Enum constant IO_ERROR
        */
        const int IO_ERROR = -137;
    } // namespace SignatureTools
} // namespace OHOS
#endif // OHOS_INDUSTRIAL_BUS_ERRNO_H