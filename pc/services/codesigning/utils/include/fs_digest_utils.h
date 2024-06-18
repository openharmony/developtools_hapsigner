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
#ifndef SIGNATURETOOLS_FS_DIGEST_UTILS_H
#define SIGNATURETOOLS_FS_DIGEST_UTILS_H

#include <string>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/ec.h>
#include <openssl/pkcs12.h>
#include <memory>
#include <map>

#include "signature_tools_log.h"

using hashFunc = const EVP_MD* (*)(void);

enum HashType {
    HASH_SHA256,
    HASH_SHA384
};

class DigestUtils {
public:
    enum class Type :char {
        BINARY, HEX
    };
    explicit DigestUtils(HashType type);
    ~DigestUtils();
    // 添加数据
    void AddData(std::string data);
    void AddData(const char* data, int length);
    // 对Base64编码的CRL字符串进行解码得到CRL对象
    X509_CRL* ParseBase64DecodedCRL(const std::string& decodedCRL);
    // 通过base64编码的字符串得到X506结构体
    X509* DecodeBase64ToX509Certifate(const std::string& encodestring);
    // 计算哈希值
    std::string Result(Type type = Type::HEX);

private:
    EVP_MD_CTX* m_ctx = NULL;
    HashType m_type;
};
#endif // SIGNATURETOOLS_FS_DIGEST_UTILS_H
