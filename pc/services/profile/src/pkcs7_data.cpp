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

#include <vector>
#include <algorithm>
#include <string>
#include <cassert>

#include "signature_tools_log.h"
#include "signature_tools_errno.h"
#include "verify_hap_openssl_utils.h"
#include "signer.h"
#include "securec.h"
#include "constant.h"
#include "pkcs7_data.h"
#include "verify_cert_openssl_utils.h"

namespace OHOS {
namespace SignatureTools {

static int PKCS7AddAttribute(PKCS7* p7, const std::vector<PKCS7Attr>& attrs)
{
    STACK_OF(PKCS7_SIGNER_INFO)* signerInfos = PKCS7_get_signer_info(p7);
    if (signerInfos == NULL || sk_PKCS7_SIGNER_INFO_num(signerInfos) != 1) {
        SIGNATURE_TOOLS_LOGE("signer info count not equal 1 or invalid signerInfos");
        return INVALIDPARAM_ERROR;
    }
    PKCS7_SIGNER_INFO* signerInfo = sk_PKCS7_SIGNER_INFO_value(signerInfos, 0);
    for (PKCS7Attr attr : attrs) {
        if (PKCS7_add_signed_attribute(signerInfo, attr.nid, attr.atrtype, attr.value) != 1) {
            if (attr.atrtype == V_ASN1_UTF8STRING)
                ASN1_STRING_free(reinterpret_cast<ASN1_STRING*>(attr.value));
            SIGNATURE_TOOLS_LOGE("PKCS7 add  attribute error!");
            return RET_FAILED;
        }
    }
    return RET_OK;
}

static int I2dPkcs7Str(PKCS7* p7, std::string& ret)
{
    unsigned char* out = NULL; // pkcs7中导出的原始数据
    int outSize = 0;
    outSize = i2d_PKCS7(p7, &out); // 反序列化获得p7b字节流
    if (out == NULL || outSize <= 0) {
        SIGNATURE_TOOLS_LOGE("pkcs7 to der failed");
        return INVALIDPARAM_ERROR;
    }
    ret.clear();
    ret.resize(outSize);
    std::copy(out, out + outSize, &ret[0]);
    OPENSSL_free(out);
    return RET_OK;
}

static int EcPkeyCtrl(PKCS7_SIGNER_INFO* arg2)
{
    int snid = 0;
    int hnid = 0;
    X509_ALGOR* alg1;
    X509_ALGOR* alg2;
    PKCS7_SIGNER_INFO_get0_algs(arg2, NULL, &alg1, &alg2);
    if (alg1 == NULL || alg1->algorithm == NULL ||
        (hnid = OBJ_obj2nid(alg1->algorithm)) == NID_undef ||
        !OBJ_find_sigid_by_algs(&snid, hnid, NID_X9_62_id_ecPublicKey) ||
        X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0) != 1) {
        return 0;
    }
    return 1;
}

static int VerifySignature(PKCS7* p7, BIO* p7bio)
{
    STACK_OF(PKCS7_SIGNER_INFO)* skSignerInfo = NULL; // 签名信息
    int signerCount = 0; // 签名数量
    // 验证签名值
    skSignerInfo = PKCS7_get_signer_info(p7);
    signerCount = sk_PKCS7_SIGNER_INFO_num(skSignerInfo);
    for (int i = 0; i < signerCount; i++) {
        PKCS7_SIGNER_INFO* signerInfo = sk_PKCS7_SIGNER_INFO_value(skSignerInfo, i);
        X509* sigCert = PKCS7_cert_from_signer_info(p7, signerInfo);
        if (PKCS7_signatureVerify(p7bio, p7, signerInfo, sigCert) != 1) {
            SIGNATURE_TOOLS_LOGE("signature verify failed");
            return VERIFY_ERROR;
        }
    }
    return RET_OK;
}

PKCS7Data::PKCS7Data(int flags) : p7(nullptr), flags(flags)
{
}

PKCS7Data::~PKCS7Data()
{
    PKCS7_free(p7);
    this->p7 = NULL;
}

int PKCS7Data::Sign(const std::string& content, std::shared_ptr<Signer> signer,
                    const std::string& sigAlg, std::string& ret, std::vector<PKCS7Attr> attrs)
{
    int result = RET_OK;
    if ((result = InitPkcs7(content, signer, sigAlg, attrs)) < 0) {
        goto err;
    }

    // 序列化
    if ((result = I2dPkcs7Str(p7, ret)) < 0) {
        goto err;
    }
    // 释放资源
err:
    if (result < 0) {
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        PrintErrorNumberMsg("SIGN_ERROR", SIGN_ERROR, "sign content failed");
    }
    return result;
}

int PKCS7Data::Parse(const std::string& p7bBytes)
{
    const unsigned char* data = reinterpret_cast<const unsigned char*>(&p7bBytes[0]);
    return Parse(&data, static_cast<long>(p7bBytes.size()));
}
int PKCS7Data::Parse(const std::vector<signed char>& p7bBytes)
{
    const unsigned char* data = reinterpret_cast<const unsigned char*>(&p7bBytes[0]);
    return Parse(&data, static_cast<long>(p7bBytes.size()));
}
int PKCS7Data::Parse(const unsigned char** in, long len)
{
    // 若p7已被初始化 将被释放
    if (p7) {
        PKCS7_free(p7);
        p7 = NULL;
    }
    // 反序列化
    p7 = d2i_PKCS7(NULL, in, len);
    if (p7 == NULL) {
        SIGNATURE_TOOLS_LOGE("der to pkcs7 failed");
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        return INVALIDPARAM_ERROR;
    }
    return RET_OK;
}

int PKCS7Data::Verify(const std::string& content) const
{
    if (VerifySign(content) < 0) {
        SIGNATURE_TOOLS_LOGE("signature verify failed");
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "signature verify failed");
        return VERIFY_ERROR;
    }
    if (VerifyCertChain() < 0) {
        SIGNATURE_TOOLS_LOGE("cert Chain verify failed:");
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "cert Chain verify failed");
        PrintCertChainSub(p7->d.sign->cert);
        return VERIFY_ERROR;
    }
    return RET_OK;
}

int PKCS7Data::GetContent(std::string& originalRawData) const
{
    BIO* oriBio = PKCS7_dataDecode(p7, NULL, NULL, NULL);
    if (oriBio == NULL) {
        SIGNATURE_TOOLS_LOGE("get pkcs7 raw data failed！");
        BIO_free_all(oriBio);
        return INVALIDPARAM_ERROR;
    }
    char buf[BUFFER_SIZE]{ 0 };
    size_t readBytes = 0;
    while (BIO_read_ex(oriBio, buf, sizeof(buf), &readBytes) == 1) {
        originalRawData.append(buf, readBytes);
    }
    BIO_free_all(oriBio);
    return RET_OK;
}
static void PKCS7AddCrls(PKCS7* p7, STACK_OF(X509_CRL)* crls)
{
    for (int i = 0; i < sk_X509_CRL_num(crls); i++) {
        PKCS7_add_crl(p7, sk_X509_CRL_value(crls, i));
    }
}
int PKCS7Data::InitPkcs7(const std::string& content, std::shared_ptr<Signer> signer,
                         const std::string& sigAlg, std::vector<PKCS7Attr> attrs)
{
    STACK_OF(X509)* certs = NULL;
    STACK_OF(X509)* certsDup = NULL; // certs的拷贝 并会去除掉实体证书
    const EVP_MD* md = NULL; // 摘要算法
    X509* cert = NULL; // 实体证书
    int result = RET_OK;
    if (signer == NULL) {
        SIGNATURE_TOOLS_LOGE("NULL signer");
        result = INVALIDPARAM_ERROR;
        goto err;
    }
    this->signer = signer;
    this->sigAlg = sigAlg;
    certs = signer->GetCertificates();
    if (sk_X509_num(certs) < MIN_CERTS_NUM) {
        SIGNATURE_TOOLS_LOGE("Error certChain count");
        result = INVALIDPARAM_ERROR;
        goto err;
    }
    certsDup = sk_X509_dup(certs);
    if (certsDup == NULL) {
        SIGNATURE_TOOLS_LOGE("dup certs failed");
        result = INVALIDPARAM_ERROR;
        goto err;
    }
    if (sigAlg == SIGN_ALG_SHA384) {
        md = EVP_sha384();
    } else if (sigAlg == SIGN_ALG_SHA256) {
        md = EVP_sha256();
    } else {
        SIGNATURE_TOOLS_LOGE("Error sigAlg please use SHAwith384 or SHAwith256");
        result = INVALIDPARAM_ERROR;
        goto err;
    }
    cert = sk_X509_delete(certsDup, 0); // 从证书链中分离出实体证书
    this->p7 = Pkcs7Sign(cert, certsDup, md, content, this->flags, attrs);
    if (this->p7 == NULL) {
        SIGNATURE_TOOLS_LOGE("pkcs7 sign content failed");
        result = SIGN_ERROR;
        goto err;
    }
    PKCS7AddCrls(p7, signer->GetCrls());

err:
    sk_X509_free(certsDup);
    return result;
}

void PKCS7Data::ReverseX509Stack(STACK_OF(X509)* certs)
{
    if (certs == NULL)
        return;
    std::vector<X509*> certChain;
    for (int i = 0; i < sk_X509_num(certs); i++) {
        certChain.push_back(sk_X509_value(certs, i));
    }
    std::reverse(certChain.begin(), certChain.end());
    while (sk_X509_num(certs))sk_X509_pop(certs);
    for (int i = 0; i < static_cast<int>(certChain.size()); i++)
        sk_X509_push(certs, certChain[i]);
}

void PKCS7Data::PrintCertChainSub(const STACK_OF(X509)* certs)
{
    if (certs == NULL)
        return;
    SIGNATURE_TOOLS_LOGI("certChainSubject:");
    int certNum = sk_X509_num(certs);
    SIGNATURE_TOOLS_LOGI("certNum%{public}s", std::to_string(certNum).c_str());
    for (int i = 0; i < certNum; i++) {
        SIGNATURE_TOOLS_LOGI("certificate %{public}s", std::to_string(i).c_str());
        std::string sub;
        VerifyCertOpensslUtils::GetSubjectFromX509(sk_X509_value(certs, i), sub);
        SIGNATURE_TOOLS_LOGI("%{public}s", sub.c_str());
    }
}

std::string PKCS7Data::GetASN1Time(const ASN1_TIME* asn1_tm)
{
    if (asn1_tm == NULL) {
        return "";
    }
    // 将ASN1_TIME结构转换为标准的tm结构
    struct tm tm_time;
    ASN1_TIME_to_tm(asn1_tm, &tm_time);
    // 转换为本地时间（考虑时区）
    time_t t = mktime(&tm_time);
    if (t < 0)
        return "";
    struct tm* local_time = localtime(&t);
    if (local_time == nullptr)
        return "";
    // 打印本地时间
    char buf[128] = { 0 };
    if (sprintf_s(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
        local_time->tm_year + YEAR1900, local_time->tm_mon + 1, local_time->tm_mday,
        local_time->tm_hour, local_time->tm_min, local_time->tm_sec) == -1) {
        return "";
    }
    return std::string(buf, strlen(buf));
}

bool PKCS7Data::X509NameCompare(const X509* cert, const X509* issuerCert)
{
    if (cert == nullptr || issuerCert == nullptr) {
        SIGNATURE_TOOLS_LOGE("NULL Cert");
        return false;
    }
    X509_NAME* aName = X509_get_issuer_name(cert);
    X509_NAME* bName = X509_get_subject_name(issuerCert);
    if (X509_NAME_cmp(aName, bName) != 0) {
        return false;
    }
    return true;
}

int PKCS7Data::CheckSignTimeInValidPeriod(const ASN1_TYPE* signTime,
                                          const ASN1_TIME* notBefore, const ASN1_TIME* notAfter)
{
    if (notBefore == nullptr || notBefore->data == nullptr || notAfter == nullptr || notAfter->data == nullptr) {
        SIGNATURE_TOOLS_LOGE("no valid period");
        return INVALIDPARAM_ERROR;
    }
    if (signTime == nullptr || signTime->value.asn1_string == nullptr ||
        signTime->value.asn1_string->data == nullptr) {
        SIGNATURE_TOOLS_LOGE("signTime is invalid");
        return INVALIDPARAM_ERROR;
    }
    ASN1_TIME* asn1_tm = ASN1_TIME_new();
    ASN1_TIME_set_string(asn1_tm, (reinterpret_cast<const char*>(signTime->value.asn1_string->data)));
    if (ASN1_TIME_compare(notBefore, signTime->value.asn1_string) > 0 ||
        ASN1_TIME_compare(notAfter, signTime->value.asn1_string) < 0) {
        SIGNATURE_TOOLS_LOGE("sign time invalid, signTime: %{public}s, notBefore: %{public}s, "
                             "notAfter: %{public}s", GetASN1Time(asn1_tm).c_str(),
                             GetASN1Time(notBefore).c_str(), GetASN1Time(notAfter).c_str());
        ASN1_TIME_free(asn1_tm);
        return RET_FAILED;
    }
    ASN1_TIME_free(asn1_tm);
    return RET_OK;
}

void PKCS7Data::SortX509Stack(STACK_OF(X509)* certs)
{
    if (certs == NULL || sk_X509_num(certs) == 0)
        return;
    if (X509NameCompare(sk_X509_value(certs, 0), sk_X509_value(certs, 0)) == true) {
        ReverseX509Stack(certs);
    }
}

int PKCS7Data::VerifySign(const std::string& content)const
{
    BIO* inBio = NULL;
    if (this->flags & PKCS7_DETACHED) {
        inBio = BIO_new_mem_buf(reinterpret_cast<const void*>(content.c_str()),
                                static_cast<int>(content.size()));
        if (inBio == NULL) {
            SIGNATURE_TOOLS_LOGE("new mem buf error!");
            return MEMORY_ALLOC_ERROR;
        }
    }
    if (PKCS7_verify(p7, NULL, NULL, inBio, NULL, this->flags) != 1) {
        BIO_free(inBio);
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        return VERIFY_ERROR;
    }
    BIO_free(inBio);
    return RET_OK;
}

int PKCS7Data::VerifyCertChain()const
{
    // 验证证书链
    STACK_OF(PKCS7_SIGNER_INFO)* skSignerInfo = PKCS7_get_signer_info(p7);
    int signerCount = sk_PKCS7_SIGNER_INFO_num(skSignerInfo);
    int c = signerCount;
    int result = RET_OK;
    // 原始证书链
    STACK_OF(X509)* certChain = p7->d.sign->cert;
    // 证书链拷贝 后面会去除实体证书
    STACK_OF(X509)* certs = sk_X509_dup(certChain);
    SortX509Stack(certs);
    // 获取只含实体证书的证书链
    while (c--)
        sk_X509_delete(certs, 0);
    for (int i = 0; i < signerCount; i++) {
        PKCS7_SIGNER_INFO* signerInfo = sk_PKCS7_SIGNER_INFO_value(skSignerInfo, i);
        if ((result = VerifySignerInfoCertchain(p7, signerInfo, certs, certChain)) < 0) {
            sk_X509_free(certs);
            return result;
        }
        sk_X509_free(certs);
    }
    return RET_OK;
}

int PKCS7Data::CheckSginerInfoSignTimeInCertChainValidPeriod(PKCS7_SIGNER_INFO* signerInfo,
                                                             STACK_OF(X509)* certs) const
{
    if (signerInfo == NULL || certs == NULL) {
        SIGNATURE_TOOLS_LOGE("invalid input");
        return INVALIDPARAM_ERROR;
    }
    ASN1_TYPE* signTime = PKCS7_get_signed_attribute(signerInfo, NID_pkcs9_signingTime);
    for (int i = 0; i < sk_X509_num(certs); i++) {
        X509* cert = sk_X509_value(certs, i);
        const ASN1_TIME* notBefore = X509_get0_notBefore(cert);
        const ASN1_TIME* notAfter = X509_get0_notAfter(cert);
        if (CheckSignTimeInValidPeriod(signTime, notBefore, notAfter) < 0) {
            SIGNATURE_TOOLS_LOGE("Error sign time");
            return INVALIDPARAM_ERROR;
        }
    }
    return RET_OK;
}

int PKCS7Data::VerifySignerInfoCertchain(PKCS7* p7, PKCS7_SIGNER_INFO* signerInfo,
                                         STACK_OF(X509)* certs, STACK_OF(X509)* certChain)const
{
    X509* sigCert = PKCS7_cert_from_signer_info(p7, signerInfo);
    int j = 0;
    // 通过主题信息追溯 并验证每个证书签名值
    if (X509NameCompare(sigCert, sk_X509_value(certs, 0)) == false) {
        SIGNATURE_TOOLS_LOGE("sigCert subject not matched");
        return VERIFY_ERROR;
    }
    if (VerifyCertOpensslUtils::CertVerify(sigCert, sk_X509_value(certs, 0)) == false) { // 验证实体证书签名值
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "entity cert signature verifitication failed");
        SIGNATURE_TOOLS_LOGE("sigCert signature verifitication failed");
        return VERIFY_ERROR;
    }
    for (; j + 1 < sk_X509_num(certs); j++) {
        if (X509NameCompare(sk_X509_value(certs, j), sk_X509_value(certs, j + 1)) == false) {
            SIGNATURE_TOOLS_LOGE("middle cert subject not matched");
            return VERIFY_ERROR;
        }
        // 验证中间证书签名值
        if (VerifyCertOpensslUtils::CertVerify(sk_X509_value(certs, j), sk_X509_value(certs, j + 1)) == false) {
            PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "sub ca cert signature verifitication failed");
            SIGNATURE_TOOLS_LOGE("middle cert signature verifitication failed");
            return VERIFY_ERROR;
        }
    }
    if (X509NameCompare(sk_X509_value(certs, j), sk_X509_value(certs, j)) == false) {
        SIGNATURE_TOOLS_LOGE("root cert subject not matched");
        return VERIFY_ERROR;
    }
    // 验证根证书签名值
    if (VerifyCertOpensslUtils::CertVerify(sk_X509_value(certs, j), sk_X509_value(certs, j)) == false) { // 验证根证书签名值
        SIGNATURE_TOOLS_LOGE("root cert signature verifitication failed");
        return VERIFY_ERROR;
    }
    // 验证签名信息中的签名时间在证书链有效期内(实体证书会在PKCS7_verify中得到验证)
    if (CheckSginerInfoSignTimeInCertChainValidPeriod(signerInfo, certChain) < 0) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "sign time not invalid");
        SIGNATURE_TOOLS_LOGE("sign time not invalid");
        return VERIFY_ERROR;
    }
    return RET_OK;
}

int PKCS7Data::Pkcs7SignerInfoSign(PKCS7_SIGNER_INFO* si)
{
    unsigned char* abuf = NULL;
    int alen;

    std::string data;
    std::string signature;
    unsigned char* sigret = NULL;
    int siglen = 0;
    int result = 0;

    alen = ASN1_item_i2d((ASN1_VALUE*)si->auth_attr, &abuf,
                         ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
    if (!abuf)
        goto err;

    data.assign(reinterpret_cast<const char*>(abuf), alen);
    signature = signer->GetSignature(data, this->sigAlg);
    if (signature.empty()) {
        goto err;
    }
    siglen = signature.size();
    sigret = reinterpret_cast<unsigned char*>(OPENSSL_malloc(siglen));
    std::copy(&signature[0], &signature[0] + signature.size(), sigret);
    ASN1_STRING_set0(si->enc_digest, sigret, siglen);

    result = 1;

err:
    OPENSSL_free(abuf);
    return result;
}

static ASN1_OCTET_STRING* PKCS7_get_octet_string2(PKCS7* p7)
{
    if (PKCS7_type_is_data(p7))
        return p7->d.data;
    return NULL;
}

int PKCS7Data::DoPkcs7SignedAttrib(PKCS7_SIGNER_INFO* si, EVP_MD_CTX* mctx)
{
    unsigned char md_data[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    /* Add signing time if not already present */
    if (!PKCS7_get_signed_attribute(si, NID_pkcs9_signingTime)) {
        if (!PKCS7_add0_attrib_signing_time(si, NULL)) {
            PKCS7err(PKCS7_F_DO_PKCS7_SIGNED_ATTRIB, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    /* Add digest */
    if (!EVP_DigestFinal_ex(mctx, md_data, &md_len)) {
        PKCS7err(PKCS7_F_DO_PKCS7_SIGNED_ATTRIB, ERR_R_EVP_LIB);
        return 0;
    }
    if (!PKCS7_add1_attrib_digest(si, md_data, md_len)) {
        PKCS7err(PKCS7_F_DO_PKCS7_SIGNED_ATTRIB, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /* Now sign the attributes */
    if (!Pkcs7SignerInfoSign(si))
        return 0;

    return 1;
}

static BIO* PKCS7_find_digest(EVP_MD_CTX** pmd, BIO* bio, int nid)
{
    while (true) {
        bio = BIO_find_type(bio, BIO_TYPE_MD);
        if (bio == NULL) {
            PKCS7err(PKCS7_F_PKCS7_FIND_DIGEST,
                     PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
            return NULL;
        }
        BIO_get_md_ctx(bio, pmd);
        if (*pmd == NULL) {
            PKCS7err(PKCS7_F_PKCS7_FIND_DIGEST, ERR_R_INTERNAL_ERROR);
            return NULL;
        }
        if (EVP_MD_CTX_type(*pmd) == nid)
            return bio;
        bio = BIO_next(bio);
    }
    return NULL;
}

static int PKCS7_dataFinal2_check(PKCS7* p7, BIO* bio,
                                  STACK_OF(PKCS7_SIGNER_INFO)** psk, ASN1_OCTET_STRING** pos)
{
    int i = 0;

    if (p7 == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (p7->d.ptr == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_NO_CONTENT);
        return 0;
    }

    i = OBJ_obj2nid(p7->type);
    p7->state = PKCS7_S_HEADER;

    switch (i) {
        case NID_pkcs7_signed:
            *psk = p7->d.sign->signer_info;
            *pos = PKCS7_get_octet_string2(p7->d.sign->contents);
            /* If detached data then the content is excluded */
            if (PKCS7_type_is_data(p7->d.sign->contents) && p7->detached) {
                ASN1_OCTET_STRING_free(*pos);
                *pos = NULL;
                p7->d.sign->contents->d.data = NULL;
            }
            break;
        default:
            PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
            return 0;
    }
    return 1;
}

int PKCS7Data::Pkcs7DataFinalSignAttr(STACK_OF(PKCS7_SIGNER_INFO)* si_sk, BIO* bio)
{
    EVP_MD_CTX* mdc = NULL;
    EVP_MD_CTX* ctx_tmp = NULL;
    STACK_OF(X509_ATTRIBUTE)* sk = NULL;
    BIO* btmp = NULL;
    int ret = 0;

    ctx_tmp = EVP_MD_CTX_new();
    if (ctx_tmp == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (si_sk != NULL) {
        for (int i = 0; i < sk_PKCS7_SIGNER_INFO_num(si_sk); i++) {
            PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(si_sk, i);

            int j = OBJ_obj2nid(si->digest_alg->algorithm);

            btmp = bio;

            btmp = PKCS7_find_digest(&mdc, btmp, j);

            /*
            * We now have the EVP_MD_CTX, lets do the signing.
            */
            if (btmp == NULL || !EVP_MD_CTX_copy_ex(ctx_tmp, mdc))
                goto err;

            sk = si->auth_attr;

            /*
            * If there are attributes, we add the digest attribute and only
            * sign the attributes
            */
            if (sk_X509_ATTRIBUTE_num(sk) > 0) {
                if (!DoPkcs7SignedAttrib(si, ctx_tmp))
                    goto err;
            } else {
                unsigned char* abuf = NULL;
                unsigned int abuflen = 0;
                abuflen = EVP_PKEY_size(si->pkey);
                abuf = reinterpret_cast<unsigned char*>(OPENSSL_malloc(abuflen));
                if (abuf == NULL)
                    goto err;

                if (!EVP_SignFinal(ctx_tmp, abuf, &abuflen, si->pkey)) {
                    OPENSSL_free(abuf);
                    PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_EVP_LIB);
                    goto err;
                }
                ASN1_STRING_set0(si->enc_digest, abuf, abuflen);
            }
        }
    }
    ret = 1;
err:
    EVP_MD_CTX_free(ctx_tmp);
    return ret;
}

static int PKCS7_dataFinal2_set_content(PKCS7* p7, ASN1_OCTET_STRING* os, BIO* bio)
{
    BIO* btmp = NULL;
    int ret = 0;
    if (!PKCS7_is_detached(p7)) {
        /*
        * NOTE(emilia): I think we only reach os == NULL here because detached
        * digested data support is broken.
        */
        if (os == NULL)
            goto err;
        if (!(os->flags & ASN1_STRING_FLAG_NDEF)) {
            char* cont;
            long contlen;
            btmp = BIO_find_type(bio, BIO_TYPE_MEM);
            if (btmp == NULL) {
                PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_UNABLE_TO_FIND_MEM_BIO);
                goto err;
            }
            contlen = BIO_get_mem_data(btmp, &cont);
            /*
            * Mark the BIO read only then we can use its copy of the data
            * instead of making an extra copy.
            */
            BIO_set_flags(btmp, BIO_FLAGS_MEM_RDONLY);
            BIO_set_mem_eof_return(btmp, 0);
            ASN1_STRING_set0(os, (unsigned char*)cont, contlen);
        }
    }
    ret = 1;
err:
    return ret;
}
int PKCS7Data::Pkcs7DataFinal(PKCS7* p7, BIO* bio)
{
    int ret = 0;
    STACK_OF(PKCS7_SIGNER_INFO)* si_sk = NULL;
    ASN1_OCTET_STRING* os = NULL;

    if (!PKCS7_dataFinal2_check(p7, bio, &si_sk, &os) ||
        !Pkcs7DataFinalSignAttr(si_sk, bio) ||
        !PKCS7_dataFinal2_set_content(p7, os, bio))
        goto err;
    ret = 1;
err:
    return ret;
}

int PKCS7Data::Pkcs7Final(PKCS7* p7, const std::string& content, int flags)
{
    BIO* p7bio;
    int ret = 0;

    if ((p7bio = PKCS7_dataInit(p7, NULL)) == NULL) {
        PKCS7err(PKCS7_F_PKCS7_FINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (BIO_write(p7bio, content.c_str(), static_cast<int>(content.size())) <= 0) {
        SIGNATURE_TOOLS_LOGE("add json data to pkcs7 failed");
        goto err;
    }

    (void)BIO_flush(p7bio);

    if (!Pkcs7DataFinal(p7, p7bio)) {
        PKCS7err(PKCS7_F_PKCS7_FINAL, PKCS7_R_PKCS7_DATASIGN);
        goto err;
    }
    // 验证签名值
    if (VerifySignature(p7, p7bio) < 0) {
        goto err;
    }
    ret = 1;

err:
    BIO_free_all(p7bio);
    return ret;
}

static int PKCS7_SIGNER_INFO_set2(PKCS7_SIGNER_INFO* p7i, X509* x509, const EVP_MD* dgst)
{
    int ret = 0;

    /* We now need to add another PKCS7_SIGNER_INFO entry */
    if (!ASN1_INTEGER_set(p7i->version, 1) ||
        !X509_NAME_set(&p7i->issuer_and_serial->issuer, X509_get_issuer_name(x509)))
        goto err;

    /*
    * because ASN1_INTEGER_set is used to set a 'long' we will do things the
    * ugly way.
    */
    ASN1_INTEGER_free(p7i->issuer_and_serial->serial);
    if (!(p7i->issuer_and_serial->serial =
        ASN1_INTEGER_dup(X509_get_serialNumber(x509))))
        goto err;

    X509_ALGOR_set0(p7i->digest_alg, OBJ_nid2obj(EVP_MD_type(dgst)),
                    V_ASN1_NULL, NULL);

    if (!EcPkeyCtrl(p7i))
        goto err;
    ret = 1;
err:
    return ret;
}

static PKCS7_SIGNER_INFO* Pkcs7AddSignature(PKCS7* p7, X509* x509, const EVP_MD* dgst)
{
    PKCS7_SIGNER_INFO* si = NULL;

    if (!(si = PKCS7_SIGNER_INFO_new()) ||
        !PKCS7_SIGNER_INFO_set2(si, x509, dgst) ||
        !PKCS7_add_signer(p7, si))
        goto err;
    return si;
err:
    PKCS7_SIGNER_INFO_free(si);
    return NULL;
}


static PKCS7_SIGNER_INFO* Pkcs7SignAddSigner(PKCS7* p7, X509* signcert, const EVP_MD* md, int flags)
{
    PKCS7_SIGNER_INFO* si = NULL;
    if ((si = Pkcs7AddSignature(p7, signcert, md)) == NULL) {
        PKCS7err(PKCS7_F_PKCS7_SIGN_ADD_SIGNER, PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR);
        return NULL;
    }
    if (!(flags & PKCS7_NOCERTS)) {
        if (!PKCS7_add_certificate(p7, signcert))
            goto err;
    }
    if (!(flags & PKCS7_NOATTR)) {
        if (!PKCS7_add_attrib_content_type(si, NULL))
            goto err;
    }
    return si;
err:
    return NULL;
}

PKCS7* PKCS7Data::Pkcs7Sign(X509* signcert, STACK_OF(X509)* certs, const EVP_MD* md,
                            const std::string& content, int flags, const std::vector<PKCS7Attr>& attrs)
{
    PKCS7* p7;
    int i;

    if (!(p7 = PKCS7_new()) ||
        !PKCS7_set_type(p7, NID_pkcs7_signed) ||
        !PKCS7_content_new(p7, NID_pkcs7_data) ||
        !Pkcs7SignAddSigner(p7, signcert, md, flags) ||
        (PKCS7AddAttribute(p7, attrs) < 0))
        goto err;

    if (!(flags & PKCS7_NOCERTS)) {
        for (i = 0; i < sk_X509_num(certs); i++) {
            if (!PKCS7_add_certificate(p7, sk_X509_value(certs, i)))
                goto err;
        }
    }

    if (flags & PKCS7_DETACHED)
        PKCS7_set_detached(p7, 1);

    if (Pkcs7Final(p7, content, flags))
        return p7;

err:
    PKCS7_free(p7);
    return NULL;
}
} // namespace SignatureTools
} // namespace OHOS