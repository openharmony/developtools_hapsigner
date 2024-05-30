/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef SIGNATURETOOLS_PARAM_CONSTANTS_H
#define SIGNATURETOOLS_PARAM_CONSTANTS_H
#include <string>
namespace OHOS {
    namespace SignatureTools {
        const std::string AAA;
        // Define const parameters
        class ParamConstants {
        public:
            /**
             * error code of hap format error.
             */
            const static int HAP_FORMAT_ERROR = 20001;
            /**
         * error code of hap parse error.
         */
            const static int HAP_PARSE_ERROR = 20002;
            /**
         * error code of hap signatures error.
         */
            const static int HAP_SIGNATURE_ERROR = 20003;
            /**
         * error code of hap signature block not found error.
         */
            const static int HAP_SIGNATURE_NOT_FOUND_ERROR = 20004;
            /**
         * Algorithm name of sha-256.
         */
            static const std::string HAP_SIG_SCHEME_V256_DIGEST_ALGORITHM;
            /**
         * Algorithm name of sha-384.
         */
            static const std::string HAP_SIG_SCHEME_V384_DIGEST_ALGORITHM;
            /**
         * Algorithm name of sha-512.
         */
            static const std::string HAP_SIG_SCHEME_V512_DIGEST_ALGORITHM;
            /**
         * Signature algorithm name of SHA256withECDSA.
         */
            static const std::string HAP_SIG_ALGORITHM_SHA256_ECDSA;
            /**
         * Signature algorithm name of SHA384withECDSA.
         */
            static const std::string HAP_SIG_ALGORITHM_SHA384_ECDSA;
            /**
         * Signature algorithm name of SHA512withECDSA.
         */
            static const std::string HAP_SIG_ALGORITHM_SHA512_ECDSA;
            /**
         * Signature algorithm name of SHA256withRSA.
         */
            static const std::string HAP_SIG_ALGORITHM_SHA256_RSA;
            /**
         * Signature algorithm name of SHA384withRSA.
         */
            static const std::string HAP_SIG_ALGORITHM_SHA384_RSA;
            /**
         * Signature algorithm name of SHA256withRSA/PSS.
         */
            static const std::string HAP_SIG_ALGORITHM_SHA256_RSA_PSS;
            /**
         * Signature algorithm name of SHA384withRSA/PSS.
         */
            static const std::string HAP_SIG_ALGORITHM_SHA384_RSA_PSS;
            /**
         * Signature algorithm name of SHA512withRSA/PSS.
         */
            static const std::string HAP_SIG_ALGORITHM_SHA512_RSA_PSS;
            /**
         * Signature algorithm name of SHA256withRSAANDMGF1.
         */
            static const std::string HAP_SIG_ALGORITHM_SHA256_RSA_MGF1;
            /**
         * Signature algorithm name of SHA384withRSAANDMGF1.
         */
            static const std::string HAP_SIG_ALGORITHM_SHA384_RSA_MGF1;
            /**
         * Signature algorithm name of SHA512withRSAANDMGF1.
         */
            static const std::string HAP_SIG_ALGORITHM_SHA512_RSA_MGF1;
            /**
         * Default value of zip-file align
         */
            static const std::string ALIGNMENT;
            /**
         * Signature mode
         */
            static const std::string PARAM_SIGN_MODE;
            /**
         * Certificate revocation list
         */
            static const std::string PARAM_BASIC_CRL;
            /**
         * Hap-file's property, stored developer info
         */
            static const std::string PARAM_BASIC_PROPERTY;
            /**
         * Hap-file's capability profile
         */
            static const std::string PARAM_BASIC_PROFILE;
            /**
         * json type content of Hap-file's capability profile
         */
            static const std::string PARAM_PROFILE_JSON_CONTENT;
            /**
         * Hap-file's proof-of-rotation
         */
            static const std::string PARAM_BASIC_PROOF;
            /**
         * Alignment
         */
            static const std::string PARAM_BASIC_ALIGNMENT;
            /**
         * Private key used in signature
         */
            static const std::string PARAM_BASIC_PRIVATE_KEY;
            /**
         * Unsigned file
         */
            static const std::string PARAM_BASIC_INPUT_FILE;
            /**
         * Signed file
         */
            static const std::string PARAM_BASIC_OUTPUT_FILE;
            /**
         * Algorithm name of signature
         */
            static const std::string PARAM_BASIC_SIGANTURE_ALG;
            /**
         * Flag indicates whether profile is signed
         */
            static const std::string PARAM_BASIC_PROFILE_SIGNED;
            /**
         * The minimum SDK version required for running the application
         */
            static const std::string PARAM_BASIC_COMPATIBLE_VERSION;
            /**
         * Url of signature server
         */
            static const std::string PARAM_REMOTE_SERVER;
            /**
         * username used in remote sign mode
         */
            static const std::string PARAM_REMOTE_USERNAME;
            /**
         * password used in remote sign mode
         */
            static const std::string PARAM_REMOTE_CODE;
            /**
         * Local keystore path
         */
            static const std::string PARAM_LOCAL_JKS_KEYSTORE;
            /**
         * The password of keystore
         */
            static const std::string PARAM_LOCAL_JKS_KEYSTORE_CODE;
            /**
         * The key alias password
         */
            static const std::string PARAM_LOCAL_JKS_KEYALIAS_CODE;
            /**
         * The certificate file path
         */
            static const std::string PARAM_LOCAL_PUBLIC_CERT;
            /**
         * The path used to output certificate-chain
         */
            static const std::string PARAM_VERIFY_CERTCHAIN_FILE;
            /**
         * The path used to output profile
         */
            static const std::string PARAM_VERIFY_PROFILE_FILE;
            /**
         * The path used to output proof-rotation file
         */
            static const std::string PARAM_VERIFY_PROOF_FILE;
            /**
         * The path used to output property file
         */
            static const std::string PARAM_VERIFY_PROPERTY_FILE;
            /**
         * The config params of resign hap
         */
            static const std::string PARAM_RESIGN_CONFIG_FILE;
            /**
         * sign file type bin or zip or elf
         */
            static const std::string PARAM_IN_FORM;
            /**
         * The code sign params of resign hap
         */
            static const std::string PARAM_SIGN_CODE;
            /**
         * file name split . of min length
         */
            static constexpr int FILE_NAME_MIN_LENGTH = 2;
            static const std::string DISABLE_SIGN_CODE;
            static const std::string ENABLE_SIGN_CODE;
        };
    }
}
#endif
