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
#ifndef SIGNERTOOLS_PKCS7DATA_H
#define SIGNERTOOLS_PKCS7DATA_H
#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/sha.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "openssl/ossl_typ.h"
#include "openssl/ec.h"
#include "openssl/asn1t.h"
#include "openssl/pkcs7.h"
#include "openssl/pkcs7err.h"
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>

namespace OHOS::SignatureTools {
#define  PKCS7_NODETACHED_FLAGS  (PKCS7_BINARY | PKCS7_NOVERIFY  | PKCS7_NOSMIMECAP)
#define  PKCS7_DETACHED_FLAGS    (PKCS7_BINARY | PKCS7_NOVERIFY  | PKCS7_NOSMIMECAP | PKCS7_DETACHED)
    struct PKCS7Attr {
        int nid;
        int atrtype;
        void* value;
    };

    class ISigner;
    class PKCS7Data {
    public:
        PKCS7Data(int flags = PKCS7_NODETACHED_FLAGS);
        PKCS7Data(const PKCS7Data& pkcs7) = delete;
        const PKCS7Data& operator=(const PKCS7Data& pkcs7) = delete;
        ~PKCS7Data();
        //对content进行签名 会初始化pkcs7 并序列化pkcs7传入ret
        int Sign(const std::string& content, std::shared_ptr<ISigner> signer, const std::string& sigAlg,
            std::string& ret, std::vector<PKCS7Attr> attrs = std::vector<PKCS7Attr>());
        int Parse(const std::string& p7bBytes);
        int Parse(const std::vector<signed char>& p7bBytes);
        int Parse(const unsigned char** in, long len);
        int Verify(const std::string& content = "")const;
        int GetContent(std::string& content) const;

        static void SortX509Stack(STACK_OF(X509)* certs);
        static void PrintCertChainSub(const STACK_OF(X509)* certs);
    private:
        int InitPkcs7(const std::string& content, std::shared_ptr<ISigner> signer,
                      const std::string& sigAlg, std::vector<PKCS7Attr> attrs);
        //验签签名值 这里不验证证书链
        int VerifySign(const std::string& content)const;
        int VerifyCertChain()const;
        //验证时间有效性
        int CheckSginerInfoSignTimeInCertChainValidPeriod(PKCS7_SIGNER_INFO* signerInfo, STACK_OF(X509)* certs)const;
        //@param cert实体证书
        //@param certs证书链(不含实体证书）
        //@param certChain证书链（含实体证书）
        //@retrun 0 success <0 error
        int VerifySignerInfoCertchain(PKCS7* p7, PKCS7_SIGNER_INFO* signerInfo,
            STACK_OF(X509)* certs, STACK_OF(X509)* certChain)const;

        static void ReverseX509Stack(STACK_OF(X509)* certs);
        static int CertVerify(X509* cert, X509* issuerCert);
        static std::string GetASN1Time(const ASN1_TIME* asn1_tm);
        static void GetTextFromX509Name(X509_NAME* name, int32_t nId, std::string& text);
        //将给定的X.509结构中的Distinguished Name（DN，即证书的主题）转换为字符串形式
        static std::string GetDnToString(X509_NAME* name);
        //从一个给定的 X509 证书中提取主题（subject）信息，并将其转换为字符串格式存储
        static int GetSubjectFromX509(const X509* cert, std::string& subject);
        //比较两个第一个证书颁发者与第二个证书主题一致
        //@return true成功 false不匹配
        static bool X509NameCompare(const X509* cert, const X509* issuerCert);
        static int CheckSignTimeInValidPeriod(const ASN1_TYPE* signTime,
                                              const ASN1_TIME* notBefore, const ASN1_TIME* notAfter);


    private:
        //以下接口为方便阅读会与openssl库接口风格尽可能一致性 没有使用大驼峰,返回值1成功 0失败
        int PKCS7_SIGNER_INFO_sign2(PKCS7_SIGNER_INFO* si);

        int do_pkcs7_signed_attrib2(PKCS7_SIGNER_INFO* si, EVP_MD_CTX* mctx);

        int PKCS7_dataFinal2_sign_attr(STACK_OF(PKCS7_SIGNER_INFO)* si_sk, BIO* bio);

        int PKCS7_dataFinal2(PKCS7* p7, BIO* bio);

        int PKCS7_final2(PKCS7* p7, const std::string& content, int flags);

        PKCS7* PKCS7_sign2(X509* signcert, STACK_OF(X509)* certs, const EVP_MD* md,
                           const std::string& content, int flags,const std::vector<PKCS7Attr>& attrs);

    private:
        PKCS7* p7 = NULL;
        int flags;
        static constexpr int BUFFER_SIZE = 4096;
        static const std::string SIGN_ALG_256;
        static const std::string SIGN_ALG_384;
        std::shared_ptr<ISigner> signer; //tmp
        std::string sigAlg; //tmp
    };
}

#endif //SIGNERTOOLS_PKCS7DATA_H