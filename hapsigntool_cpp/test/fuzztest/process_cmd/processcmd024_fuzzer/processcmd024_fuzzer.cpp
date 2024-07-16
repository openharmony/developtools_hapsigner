/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>

#include "signature_algorithm_helper.h"
#include "verify_hap_openssl_utils.h"
#include "hash_utils.h"
#include "params.h"

namespace OHOS {
namespace SignatureTools {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }

    Params param;
    std::string str;
    std::string  retStr;
    std::string  algName;
    bool retBool = false;
    int algId = 256;
    std::vector<std::string> paramFields;
    std::vector<int8_t> fileBytes;
    std::unordered_set<std::string> unordered;
    std::vector<int8_t> vec;
    int64_t length = 0;
    SignatureAlgorithmHelper out;
    ByteBuffer crlBuffer;
    int32_t offset = 0;
    int32_t len = 0;
    std::ofstream crlFile;
    CertChain certsChain;
    Pkcs7Context pkcs7Context;
    long long certNumber = 0;
    Options* options = nullptr;
    X509* cert = nullptr;
    X509_CRL* x509Crl = nullptr;

    param.SetMethod(str);
    retStr = param.GetMethod();
    options = param.GetOptions();
    unordered = param.InitParamField(paramFields);
    retBool = param.GetSignatureAlgorithm(str, out);
    retStr = HashUtils::GetHashAlgName(algId);
    vec = HashUtils::GetDigestFromBytes(fileBytes, length, algName);
    cert = VerifyCertOpensslUtils::GetX509CertFromBase64String(str);
    retBool = VerifyCertOpensslUtils::CompareX509Cert(nullptr, str);
    x509Crl = VerifyCertOpensslUtils::GetX509CrlFromDerBuffer(crlBuffer, offset, len);
    VerifyCertOpensslUtils::WriteX509CrlToStream(crlFile, nullptr);
    retBool = VerifyCertOpensslUtils::VerifyCrl(certsChain, nullptr, pkcs7Context);
    x509Crl = VerifyCertOpensslUtils::GetCrlBySignedCertIssuer(nullptr, nullptr);
    retBool = VerifyCertOpensslUtils::GetIssuerFromX509(nullptr, str);
    retBool = VerifyCertOpensslUtils::GetSerialNumberFromX509(nullptr, certNumber);
    retBool = VerifyCertOpensslUtils::GetIssuerFromX509Crl(nullptr, str);

    return true;
}
} // namespace SignatureTools
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SignatureTools::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}