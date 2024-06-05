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
#ifndef SIGNERTOOLS_STRINGUTILS_H
#define SIGNERTOOLS_STRINGUTILS_H
#include <string>
#include <vector>
#include <sstream>
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "signature_tools_log.h"
#include "verify_openssl_utils.h"
namespace OHOS {
    namespace SignatureTools {
        class StringUtils {
        private:
            StringUtils();
            /**
         * Check whether the input string is empty.
         *
         * @param cs input string
         * @return true, if cs is empty
         */
        public:
            static bool IsEmpty(const std::string& cs);
            /**
         * Check whether the array contains string ignoring case.
         *
         * @param array input string array
         * @param str input string
         * @return true, if the array contains the str ignoring case
         */
            static bool ContainsIgnoreCase(std::vector<std::string> strs, std::string str);
            static bool ContainsCase(std::vector<std::string> strs, const std::string& str);
            static bool IgnoreCaseCompare(std::string str1, std::string str2);
            static bool CaseCompare(const std::string& str1, const std::string& str2);
            static std::vector<std::string> SplitString(const std::string& str, char delimiter);
            static std::string Trim(const std::string& str);
            static std::string FormatLoading(std::string& dealStr);
            static std::string Pkcs7ToString(PKCS7* p7);
            static std::string x509CertToString(X509* cert);
            static std::string SubjectToString(X509* cert);
        };
    } // namespace SignatureTools
} // namespace OHOS
#endif // SIGNERTOOLS_STRINGUTILS_H