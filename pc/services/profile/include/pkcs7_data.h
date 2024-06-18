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
#ifndef SIGNATRUETOOLS_PKCS7DATA_H
#define SIGNATRUETOOLS_PKCS7DATA_H

#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>

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
#include "signer.h"

namespace OHOS {
namespace SignatureTools {
#define  PKCS7_NODETACHED_FLAGS  (PKCS7_BINARY | PKCS7_NOVERIFY)
#define  PKCS7_DETACHED_FLAGS    (PKCS7_BINARY | PKCS7_NOVERIFY | PKCS7_DETACHED)
struct PKCS7Attr {
    int nid;
    int atrtype;
    void* value;
};

class PKCS7Data {
public:
    PKCS7Data(int flags = PKCS7_NODETACHED_FLAGS);
    PKCS7Data(const PKCS7Data& pkcs7) = delete;
    const PKCS7Data& operator=(const PKCS7Data& pkcs7) = delete;
    ~PKCS7Data();
    /*
    * @param content 待签名数据
    * @param signer  颁发者
    * @param sigAlg  签名算法SHA256withECDSA/SHA384withECDSA
    * @param ret     返回的签名结果pkcs7
    * @param attrs   只在需要添加ownerID时使用，其他不需要处理 默认即可
    * @return        0 :success <0 :error
    */
    int Sign(const std::string& content,
             std::shared_ptr<Signer> signer,
             const std::string& sigAlg,
             std::string& ret, std::vector<PKCS7Attr> attrs = std::vector<PKCS7Attr>());
    /* d2i 反序列化 */
    int Parse(const std::string& p7bBytes);
    int Parse(const std::vector<signed char>& p7bBytes);
    /* 验证签名时使用，默认不用输入content，如果数据分离（content不在pkcs7之中 需要传入原始数据进行验证） */
    int Verify(const std::string& content = "")const;
    /* 获取pkcs7进行保护的原始数据 */
    int GetContent(std::string& content) const;
    
    /* 在C++中证书链顺序是正向的, java是反向的 此为历史原因造成 通过检查第一个证书是否是自签进行排序为正序 */
    static void SortX509Stack(STACK_OF(X509)* certs);
    /* 用于打印证书链的主题信息 */
    static void PrintCertChainSub(const STACK_OF(X509)* certs);
    static void ReverseX509Stack(STACK_OF(X509)* certs);
    static std::string GetASN1Time(const ASN1_TIME* asn1_tm);
    /* 比较两个第一个证书颁发者与第二个证书主题一致 */
    static bool X509NameCompare(const X509* cert, const X509* issuerCert);
    /* 检查签名时间在有效期内 */
    static int CheckSignTimeInValidPeriod(const ASN1_TYPE* signTime,
                                          const ASN1_TIME* notBefore, const ASN1_TIME* notAfter);

private:
    int Parse(const unsigned char** in, long len);
    int InitPkcs7(const std::string& content, std::shared_ptr<Signer> signer,
                  const std::string& sigAlg, std::vector<PKCS7Attr> attrs);
    /* 验签签名值 这里不验证证书链 */
    int VerifySign(const std::string& content)const;
    int VerifyCertChain()const;
    /* 验证时间有效性 */
    int CheckSginerInfoSignTimeInCertChainValidPeriod(PKCS7_SIGNER_INFO* signerInfo, STACK_OF(X509)* certs)const;
    /* @param cert实体证书
     * @param certs证书链(不含实体证书）
     * @param certChain证书链（含实体证书）
     * @retrun 0 success <0 error
     */
    int VerifySignerInfoCertchain(PKCS7* p7,
                                  PKCS7_SIGNER_INFO* signerInfo,
                                  STACK_OF(X509)* certs,
                                  STACK_OF(X509)* certChain)const;

private:
    /* 以下接口为方便阅读会与openssl库接口风格尽可能一致性,返回值1成功 0失败 */
    int Pkcs7SignerInfoSign(PKCS7_SIGNER_INFO* si);

    int DoPkcs7SignedAttrib(PKCS7_SIGNER_INFO* si, EVP_MD_CTX* mctx);

    int Pkcs7DataFinalSignAttr(STACK_OF(PKCS7_SIGNER_INFO)* si_sk, BIO* bio);

    int Pkcs7DataFinal(PKCS7* p7, BIO* bio);

    int Pkcs7Final(PKCS7* p7, const std::string& content, int flags);

    PKCS7* Pkcs7Sign(X509* signcert, STACK_OF(X509)* certs, const EVP_MD* md,
                     const std::string& content, int flags, const std::vector<PKCS7Attr>& attrs);

private:
    PKCS7* p7 = NULL;
    int flags;
    static constexpr int BUFFER_SIZE = 4096;
    std::shared_ptr<Signer> signer; // tmp
    std::string sigAlg; // tmp
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_PKCS7DATA_H