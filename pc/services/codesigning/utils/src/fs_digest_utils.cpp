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
#include "fs_digest_utils.h"
#include "securec.h"
void DigestUtils::AddData(std::string data)
{
    AddData(data.data(), (int)data.size());
}
void DigestUtils::AddData(const char* data, int length)
{
    int ret = EVP_DigestUpdate(m_ctx, data, length);
    if (ret < 1) {
        printf("Update DigestFunc failed!\n");
    }
}
X509_CRL* DigestUtils::ParseBase64DecodedCRL(const std::string& encodedCRL)
{
    // 将base64编码的CRL字符串转换为BIO
    BIO* bio = BIO_new_mem_buf((void*)encodedCRL.c_str(), -1);
    if (bio == nullptr) {
        printf("Error creating BIO from CRL data\n");
        return nullptr;
    }
    // 从BIO中读取PEM格式的X509_CRL结构体
    X509_CRL* crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
    if (crl == nullptr) {
        printf("Error reading X509_CRL\n");
    }
    // 释放BIO资源
    BIO_free(bio);
    return crl;
}
X509* DigestUtils::DecodeBase64ToX509Certifate(const std::string& encodeString)
{
    // 将base64编码的证书字符串转换为BIO
    BIO* bio = BIO_new_mem_buf((void*)encodeString.c_str(), -1);
    if (bio == nullptr) {
        printf("Error creating BIO from certificate data\n");
        return nullptr;
    }
    // 从BIO中读取PEM格式的X509证书
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (cert == nullptr) {
        printf("Error reading X509 certificate\n");
    }
    // 释放BIO资源
    BIO_free(bio);
    return cert;
}
std::string DigestUtils::Result(DigestUtils::Type type)
{
    unsigned int len = 0;

    const std::map<HashType, int> hashLength = {
        {HASH_SHA256, SHA256_DIGEST_LENGTH},
        {HASH_SHA384, SHA384_DIGEST_LENGTH},
    };

    unsigned char* md = reinterpret_cast<unsigned char*>(new char[hashLength.at(m_type)]);
    int ret = EVP_DigestFinal_ex(m_ctx, md, &len);
    if (ret < 1) {
        printf("Failed to Calculate Hash Relsult\n");
    }
    int temporaryVariable_1 = 2;
    int temporaryVariable_2 = 3;
    if (type == Type::HEX) {
        char* res = new char[len * temporaryVariable_1 + 1];
        for (unsigned int i = 0; i < len; i++) {
            snprintf_s(&res[i * temporaryVariable_1], temporaryVariable_2, temporaryVariable_1, "%02x", md[i]);
        }
        std::string st{ res, len * temporaryVariable_1 };
        delete[]md;
        delete[]res;
        return st;
    }
    std::string st{ reinterpret_cast<char*>(md), len };
    delete[]md;
    return st;
}
DigestUtils::DigestUtils(HashType type)
{
    m_type = type;
    // 创建并初始化哈希函数上下文
    m_ctx = EVP_MD_CTX_new();

    const std::map<HashType, hashFunc> hashMethods = {
        {HASH_SHA256, EVP_sha256},
        {HASH_SHA384, EVP_sha384}
    };

    int ret = EVP_DigestInit_ex(m_ctx, hashMethods.at(type)(), nullptr);
    if (ret < 1) {
        printf("Init DigestFunc failed!\n");
    }
}
DigestUtils::~DigestUtils()
{
    if (m_ctx != nullptr) {
        EVP_MD_CTX_free(m_ctx);
    }
}