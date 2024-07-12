/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#ifndef SINATURETOOLS_PKCS12_PARSER_H
#define SINATURETOOLS_PKCS12_PARSER_H

#include <fstream>
#include <iostream>
#include <memory>

#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs7err.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/pemerr.h>

namespace OHOS {
namespace SignatureTools {

//@return 1 success 0 failed
class PKCS12Parser {
public:
    PKCS12Parser(const std::string& storePath);
    ~PKCS12Parser();
    bool Parse(const char* name,
        const char* storePass,
        const char* keyPass,
        EVP_PKEY** outPrivateKey,
        X509** outCert,
        STACK_OF(X509)** outCertchain);
private:
    static PKCS12* Init(const std::string& path);
    bool ParsePrepare(const char* fName, const char** pstorePass, const char* keyPass, EVP_PKEY** outPrivateKey,
                      X509** outCert, STACK_OF(X509)** outCertchain, STACK_OF(X509)** poutCerts);
    bool ParseSafeBag(PKCS12_SAFEBAG* bag,
        const char* pkeyPassword,
        int passLen,
        EVP_PKEY** outPkey,
        STACK_OF(X509)* outCerts);
    bool ParseSafeBags(const STACK_OF(PKCS12_SAFEBAG)* bags,
        const char* pkeyPassword,
        int passLen,
        EVP_PKEY** outPkey,
        STACK_OF(X509)* outCerts);
    bool ParsePkcs12(const char* storePassword,
        const char* keyPassword,
        EVP_PKEY** outPrivateKey,
        STACK_OF(X509)* outCerts);
private:
    std::string friendName;
    PKCS12* p12;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SINATURETOOLS_PKCS12_PARSER_H