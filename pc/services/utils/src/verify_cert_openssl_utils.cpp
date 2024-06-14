/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.verify_cert_openssl_utils.h
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
#include "verify_cert_openssl_utils.h"
#include <cmath>
#include <fstream>

#include "openssl/pem.h"
#include "openssl/sha.h"
#include "signature_tools_log.h"
#include "securec.h"
#include "verify_hap_openssl_utils.h"

namespace OHOS {
namespace SignatureTools {

const uint32_t VerifyCertOpensslUtils::MIN_CERT_CHAIN_LEN_NEED_VERIFY_CRL = 2;
const int32_t VerifyCertOpensslUtils::OPENSSL_READ_CRL_MAX_TIME = 1048576; // 1024 * 1024
const int32_t VerifyCertOpensslUtils::OPENSSL_READ_CRL_LEN_EACH_TIME = 1024;
const int32_t VerifyCertOpensslUtils::BASE64_ENCODE_LEN_OF_EACH_GROUP_DATA = 4;
const int32_t VerifyCertOpensslUtils::BASE64_ENCODE_PACKET_LEN = 3;
constexpr int32_t BUFF_SIZE = 3;

X509* VerifyCertOpensslUtils::GetX509CertFromPemString(const std::string& pemString)
{
    BIO* pemBio = BIO_new(BIO_s_mem());
    if (pemBio == nullptr) {
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("BIO_new failed");
        return nullptr;
    }
    int32_t strLen = static_cast<int>(pemString.size());
    if (BIO_write(pemBio, pemString.c_str(), strLen) != strLen) {
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("BIO_write failed");
        BIO_free_all(pemBio);
        return nullptr;
    }
    X509* cert = PEM_read_bio_X509(pemBio, nullptr, nullptr, nullptr);
    BIO_free_all(pemBio);
    return cert;
}

X509* VerifyCertOpensslUtils::GetX509CertFromBase64String(const std::string& base64String)
{
    std::unique_ptr<unsigned char[]> decodeBuffer = std::make_unique<unsigned char[]>(base64String.size());
    const unsigned char* input = reinterpret_cast<const unsigned char*>(base64String.c_str());
    int32_t len = EVP_DecodeBlock(decodeBuffer.get(), input, base64String.size());
    if (len <= 0) {
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("base64Decode failed, len: %{public}d", len);
        return nullptr;
    }
    const unsigned char* derBits = decodeBuffer.get();
    X509* cert = d2i_X509(nullptr, &derBits, len);
    return cert;
}

bool VerifyCertOpensslUtils::GetPublickeyBase64FromPemCert(const std::string& certStr,
                                                           std::string& publicKey)
{
    X509* cert = GetX509CertFromPemString(certStr);
    if (cert == nullptr) {
        SIGNATURE_TOOLS_LOGE("GetX509CertFromPemString failed");
        return false;
    }
    if (!GetPublickeyBase64(cert, publicKey)) {
        SIGNATURE_TOOLS_LOGE("X509_get_pubkey failed");
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        X509_free(cert);
        return false;
    }
    X509_free(cert);
    return true;
}

bool VerifyCertOpensslUtils::GetFingerprintBase64FromPemCert(const std::string& certStr,
                                                             std::string& fingerprint)
{
    SIGNATURE_TOOLS_LOGD("GetFingerprintBase64FromPemCert begin");
    X509* cert = GetX509CertFromPemString(certStr);
    if (cert == nullptr) {
        SIGNATURE_TOOLS_LOGE("GetX509CertFromPemString failed");
        return false;
    }
    int32_t certLen = i2d_X509(cert, nullptr);
    if (certLen <= 0) {
        SIGNATURE_TOOLS_LOGE("certLen %{public}d, i2d_X509 failed", certLen);
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        X509_free(cert);
        return false;
    }
    std::unique_ptr<unsigned char[]> derCertificate = std::make_unique<unsigned char[]>(certLen);
    unsigned char* derCertificateBackup = derCertificate.get();
    if (i2d_X509(cert, &derCertificateBackup) <= 0) {
        SIGNATURE_TOOLS_LOGE("i2d_X509 failed");
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        X509_free(cert);
        return false;
    }
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, derCertificate.get(), certLen);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);
    char buff[BUFF_SIZE] = { 0 };
    for (int32_t index = 0; index < SHA256_DIGEST_LENGTH; ++index) {
        if (sprintf_s(buff, sizeof(buff), "%02X", hash[index]) < 0) {
            fingerprint.clear();
            SIGNATURE_TOOLS_LOGE("transforms hash string to hexadecimal string failed");
            X509_free(cert);
            return false;
        }
        fingerprint += buff;
    }
    X509_free(cert);
    SIGNATURE_TOOLS_LOGD("GetFingerprintBase64FromPemCert end %{public}s", fingerprint.c_str());
    return true;
}

bool VerifyCertOpensslUtils::GetPublickeyBase64(const X509* cert, std::string& publicKey)
{
    EVP_PKEY* pkey = X509_get0_pubkey(cert);
    if (pkey == nullptr) {
        SIGNATURE_TOOLS_LOGE("X509_get0_pubkey failed");
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        return false;
    }
    int32_t keyLen = i2d_PublicKey(pkey, nullptr);
    if (keyLen <= 0) {
        SIGNATURE_TOOLS_LOGE("keyLen %{public}d, i2d_PublicKey failed", keyLen);
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        return false;
    }
    std::unique_ptr<unsigned char[]> derPublicKey = std::make_unique<unsigned char[]>(keyLen);
    int32_t base64KeyLen = CalculateLenAfterBase64Encode(keyLen);
    std::unique_ptr<unsigned char[]> base64PublicKey = std::make_unique<unsigned char[]>(base64KeyLen);
    unsigned char* derCertificateBackup = derPublicKey.get();
    if (i2d_PublicKey(pkey, &derCertificateBackup) <= 0) {
        SIGNATURE_TOOLS_LOGE("i2d_PublicKey failed");
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        return false;
    }
    int32_t outLen = EVP_EncodeBlock(base64PublicKey.get(), derPublicKey.get(), keyLen);
    publicKey = std::string(reinterpret_cast<char*>(base64PublicKey.get()), outLen);
    return true;
}

bool VerifyCertOpensslUtils::GetOrganizationFromPemCert(const std::string& certStr,
                                                        std::string& organization)
{
    SIGNATURE_TOOLS_LOGD("GetFingerprintBase64FromPemCert begin");
    X509* cert = GetX509CertFromPemString(certStr);
    if (cert == nullptr) {
        SIGNATURE_TOOLS_LOGE("GetX509CertFromPemString failed");
        return false;
    }
    X509_NAME* name = X509_get_subject_name(cert);
    GetTextFromX509Name(name, NID_organizationName, organization);
    X509_free(cert);
    return true;
}
/*
* The length after Base64 encoding is 4/3 of the length before encoding,
* and openssl function will add '\0' to the encoded string.
* So len_after_encode = len_before_encode * 4/3 + 1
*/
int32_t VerifyCertOpensslUtils::CalculateLenAfterBase64Encode(int32_t len)
{
    return (len + BASE64_ENCODE_PACKET_LEN - 1) / BASE64_ENCODE_PACKET_LEN
        * BASE64_ENCODE_LEN_OF_EACH_GROUP_DATA + 1;
}
bool VerifyCertOpensslUtils::CompareX509Cert(const X509* certA, const std::string& base64Cert)
{
    if (certA == nullptr) {
        SIGNATURE_TOOLS_LOGE("certA is nullptr");
        return false;
    }
    X509* certB = GetX509CertFromPemString(base64Cert);
    if (certB == nullptr) {
        SIGNATURE_TOOLS_LOGE("generate certB failed");
        return false;
    }
    bool ret = (X509_cmp(certA, certB) == 0);
    X509_free(certB);
    return ret;
}

X509_CRL* VerifyCertOpensslUtils::GetX509CrlFromDerBuffer(const ByteBuffer& crlBuffer,
                                                          int32_t offset, int32_t len)
{
    if (crlBuffer.GetBufferPtr() == nullptr) {
        SIGNATURE_TOOLS_LOGE("invalid input, crlbuffer is null");
        return nullptr;
    }
    if ((len <= 0) || (offset < 0) || (crlBuffer.GetCapacity() - len < offset)) {
        SIGNATURE_TOOLS_LOGE("invalid input, offset: %{public}d, len: %{public}d", offset, len);
        return nullptr;
    }
    BIO* derBio = BIO_new(BIO_s_mem());
    if (derBio == nullptr) {
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("BIO_new failed");
        return nullptr;
    }
    if (BIO_write(derBio, crlBuffer.GetBufferPtr() + offset, len) != len) {
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("BIO_write failed");
        BIO_free_all(derBio);
        return nullptr;
    }
    X509_CRL* crl = d2i_X509_CRL_bio(derBio, nullptr);
    BIO_free_all(derBio);
    return crl;
}

void VerifyCertOpensslUtils::WriteX509CrlToStream(std::ofstream& crlFile, X509_CRL* crl)
{
    if (!crlFile.is_open()) {
        SIGNATURE_TOOLS_LOGE("fill is not open");
        return;
    }
    BIO* derBio = BIO_new(BIO_s_mem());
    if (derBio == nullptr) {
        SIGNATURE_TOOLS_LOGE("BIO_new failed");
        return;
    }
    if (crl == nullptr || i2d_X509_CRL_bio(derBio, crl) == 0) {
        BIO_free_all(derBio);
        SIGNATURE_TOOLS_LOGE("i2d_X509_CRL_bio failed");
        return;
    }
    int32_t totalLen = 0;
    long long posStart = crlFile.tellp();
    crlFile.seekp(posStart + sizeof(totalLen));
    char buf[OPENSSL_READ_CRL_LEN_EACH_TIME];
    int32_t readLen = BIO_read(derBio, buf, sizeof(buf));
    int32_t readTime = 0;
    while (readLen > 0 && (++readTime < OPENSSL_READ_CRL_MAX_TIME)) {
        crlFile.write(buf, readLen);
        totalLen += readLen;
        readLen = BIO_read(derBio, buf, sizeof(buf));
    }
    BIO_free_all(derBio);
    long long posEnd = crlFile.tellp();
    crlFile.seekp(posStart);
    /* write crl data len */
    crlFile.write(reinterpret_cast<char*>(&totalLen), sizeof(totalLen));
    crlFile.seekp(posEnd);
}

void VerifyCertOpensslUtils::GenerateCertSignFromCertStack(STACK_OF(X509)* certs, CertSign& certVisitSign)
{
    if (certs == nullptr) {
        return;
    }
    for (int32_t i = 0; i < sk_X509_num(certs); i++) {
        X509* cert = sk_X509_value(certs, i);
        if (cert == nullptr) {
            continue;
        }
        certVisitSign[cert] = false;
    }
}

void VerifyCertOpensslUtils::ClearCertVisitSign(CertSign& certVisitSign)
{
    for (auto& certPair : certVisitSign) {
        certPair.second = false;
    }
}

bool VerifyCertOpensslUtils::GetCertsChain(CertChain& certsChain, CertSign& certVisitSign)
{
    if (certsChain.empty() || certVisitSign.empty()) {
        SIGNATURE_TOOLS_LOGE("input is invalid");
        return false;
    }
    X509* issuerCert;
    X509* cert = certsChain[0];
    while ((issuerCert = FindCertOfIssuer(cert, certVisitSign)) != nullptr) {
        certsChain.push_back(X509_dup(issuerCert));
        certVisitSign[issuerCert] = true;
        cert = issuerCert;
    }
    if (CertVerify(cert, cert) == false) {
        SIGNATURE_TOOLS_LOGE("CertVerify is invalid");
        return false;
    }
    {
        X509_NAME* aName = X509_get_issuer_name(cert);
        X509_NAME* bName = X509_get_subject_name(cert);
        if (aName == NULL || bName == NULL) {
            printf("NULL X509_NAME\n");
            return false;
        }
        if (X509_NAME_cmp(aName, bName) != 0) {
            printf("compare error!\n");
            return false;
        }
        return true;
    }
}

X509* VerifyCertOpensslUtils::FindCertOfIssuer(X509* cert, CertSign& certVisitSign)
{
    if (cert == nullptr) {
        SIGNATURE_TOOLS_LOGE("input is invalid");
        return nullptr;
    }
    X509_NAME* signCertIssuer = X509_get_issuer_name(cert);
    for (auto certPair : certVisitSign) {
        if (certPair.second) {
            continue;
        }
        X509* issuerCert = certPair.first;
        X509_NAME* issuerCertSubject = X509_get_subject_name(issuerCert);
        /* verify sign and issuer */
        if (X509NameCompare(issuerCertSubject, signCertIssuer) &&
            CertVerify(cert, issuerCert)) {
            return issuerCert;
        }
    }
    return nullptr;
}

bool VerifyCertOpensslUtils::CertVerify(X509* cert, const X509* issuerCert)
{
    if (cert == nullptr) {
        SIGNATURE_TOOLS_LOGE("input is invalid");
        return false;
    }
    EVP_PKEY* caPublicKey = X509_get0_pubkey(issuerCert);
    if (caPublicKey == nullptr) {
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("get pubkey from caCert failed");
        return false;
    }
    return X509_verify(cert, caPublicKey) > 0;
}

bool VerifyCertOpensslUtils::VerifyCertChainPeriodOfValidity(CertChain& certsChain,
                                                             const ASN1_TYPE* signTime)
{
    if (certsChain.empty()) {
        return false;
    }
    for (uint32_t i = 0; i < certsChain.size() - 1; i++) {
        if (certsChain[i] == nullptr) {
            SIGNATURE_TOOLS_LOGE("%{public}dst cert is nullptr", i);
            return false;
        }
        const ASN1_TIME* notBefore = X509_get0_notBefore(certsChain[i]);
        const ASN1_TIME* notAfter = X509_get0_notAfter(certsChain[i]);
        if (!CheckSignTimeInValidPeriod(signTime, notBefore, notAfter)) {
            SIGNATURE_TOOLS_LOGE("%{public}dst cert is not in period of validity", i);
            return false;
        }
    }
    return true;
}

bool VerifyCertOpensslUtils::CheckAsn1TimeIsValid(const ASN1_TIME* asn1Time)
{
    if (asn1Time == nullptr || asn1Time->data == nullptr) {
        return false;
    }
    return true;
}

bool VerifyCertOpensslUtils::CheckAsn1TypeIsValid(const ASN1_TYPE* asn1Type)
{
    if (asn1Type == nullptr || asn1Type->value.asn1_string == nullptr ||
        asn1Type->value.asn1_string->data == nullptr) {
        return false;
    }
    return true;
}

bool VerifyCertOpensslUtils::CheckSignTimeInValidPeriod(const ASN1_TYPE* signTime,
                                                        const ASN1_TIME* notBefore,
                                                        const ASN1_TIME* notAfter)
{
    if (!CheckAsn1TimeIsValid(notBefore) || !CheckAsn1TimeIsValid(notAfter)) {
        SIGNATURE_TOOLS_LOGE("no valid period");
        return false;
    }
    if (!CheckAsn1TypeIsValid(signTime)) {
        SIGNATURE_TOOLS_LOGE("signTime is invalid");
        return false;
    }
    if (ASN1_TIME_compare(notBefore, signTime->value.asn1_string) > 0 ||
        ASN1_TIME_compare(notAfter, signTime->value.asn1_string) < 0) {
        SIGNATURE_TOOLS_LOGE("Out of valid period, signTime: %{public}s, "
                             "notBefore:%{public}s, notAfter : %{public}s",
                             signTime->value.asn1_string->data, notBefore->data, notAfter->data);
        return false;
    }
    SIGNATURE_TOOLS_LOGD("signTime type: %{public}d, data: %{public}s, "
                         "notBefore:%{public}s, notAfter : %{public}s",
                         signTime->type, signTime->value.asn1_string->data,
                         notBefore->data, notAfter->data);
    return true;
}

bool VerifyCertOpensslUtils::VerifyCrl(CertChain& certsChain, STACK_OF(X509_CRL)* crls,
                                       Pkcs7Context& pkcs7Context)
{
    if (certsChain.empty()) {
        SIGNATURE_TOOLS_LOGE("cert chain is null");
        return false;
    }
    /* get signed cert's issuer and then it will be used to find local crl */
    if (!GetIssuerFromX509(certsChain[0], pkcs7Context.certIssuer)) {
        SIGNATURE_TOOLS_LOGE("get issuer of signed cert failed");
        return false;
    }
    X509_CRL* targetCrl = GetCrlBySignedCertIssuer(crls, certsChain[0]);
    /* crl is optional */
    if (targetCrl != nullptr && certsChain.size() >= MIN_CERT_CHAIN_LEN_NEED_VERIFY_CRL) {
        /* if it include crl, it must be verified by ca cert */
        if (X509_CRL_verify(targetCrl, X509_get0_pubkey(certsChain[1])) <= 0) {
            VerifyHapOpensslUtils::GetOpensslErrorMessage();
            SIGNATURE_TOOLS_LOGE("verify crlInPackage failed");
            return false;
        }
    }
    return true;
}

X509_CRL* VerifyCertOpensslUtils::GetCrlBySignedCertIssuer(STACK_OF(X509_CRL)* crls, const X509* cert)
{
    if (crls == nullptr || cert == nullptr) {
        return nullptr;
    }
    X509_NAME* certIssuer = X509_get_issuer_name(cert);
    for (int32_t i = 0; i < sk_X509_CRL_num(crls); i++) {
        X509_CRL* crl = sk_X509_CRL_value(crls, i);
        if (crl == nullptr) {
            continue;
        }
        X509_NAME* crlIssuer = X509_CRL_get_issuer(crl);
        if (X509NameCompare(crlIssuer, certIssuer)) {
            return crl;
        }
    }
    return nullptr;
}

bool VerifyCertOpensslUtils::X509NameCompare(const X509_NAME* a, const X509_NAME* b)
{
    if (a == nullptr || b == nullptr) {
        return false;
    }
    return X509_NAME_cmp(a, b) == 0;
}

bool VerifyCertOpensslUtils::GetSubjectFromX509(const X509* cert, std::string& subject)
{
    if (cert == nullptr) {
        SIGNATURE_TOOLS_LOGE("cert is nullptr");
        return false;
    }
    X509_NAME* name = X509_get_subject_name(cert);
    subject = GetDnToString(name);
    SIGNATURE_TOOLS_LOGD("subject = %{public}s", subject.c_str());
    return true;
}

bool VerifyCertOpensslUtils::GetIssuerFromX509(const X509* cert, std::string& issuer)
{
    if (cert == nullptr) {
        SIGNATURE_TOOLS_LOGE("cert is nullptr");
        return false;
    }
    X509_NAME* name = X509_get_issuer_name(cert);
    issuer = GetDnToString(name);
    SIGNATURE_TOOLS_LOGD("cert issuer = %{public}s", issuer.c_str());
    return true;
}

bool VerifyCertOpensslUtils::GetSerialNumberFromX509(const X509* cert, long long& certNumber)
{
    if (cert == nullptr) {
        SIGNATURE_TOOLS_LOGE("cert is nullptr");
        return false;
    }
    const ASN1_INTEGER* certSN = X509_get0_serialNumber(cert);
    certNumber = ASN1_INTEGER_get(certSN);
    SIGNATURE_TOOLS_LOGD("cert number = %{public}lld", certNumber);
    return true;
}

bool VerifyCertOpensslUtils::GetIssuerFromX509Crl(const X509_CRL* crl, std::string& issuer)
{
    if (crl == nullptr) {
        SIGNATURE_TOOLS_LOGE("clr is nullptr");
        return false;
    }
    X509_NAME* name = X509_CRL_get_issuer(crl);
    if (name == nullptr) {
        SIGNATURE_TOOLS_LOGE("crl issuer nullptr");
        return false;
    }
    issuer = GetDnToString(name);
    return true;
}

std::string VerifyCertOpensslUtils::GetDnToString(X509_NAME* name)
{
    if (name == nullptr) {
        return "";
    }
    std::string countryName;
    GetTextFromX509Name(name, NID_countryName, countryName);
    std::string organizationName;
    GetTextFromX509Name(name, NID_organizationName, organizationName);
    std::string organizationalUnitName;
    GetTextFromX509Name(name, NID_organizationalUnitName, organizationalUnitName);
    std::string commonName;
    GetTextFromX509Name(name, NID_commonName, commonName);
    return "C=" + countryName + ", O=" + organizationName + ", OU=" + organizationalUnitName +
        ", CN=" + commonName;
}

void VerifyCertOpensslUtils::GetTextFromX509Name(X509_NAME* name, int32_t nId, std::string& text)
{
    int32_t textLen = X509_NAME_get_text_by_NID(name, nId, nullptr, 0);
    if (textLen <= 0) {
        return;
    }
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(textLen + 1);
    if (X509_NAME_get_text_by_NID(name, nId, buffer.get(), textLen + 1) != textLen) {
        return;
    }
    text = std::string(buffer.get());
}
} // namespace SignatureTools
} // namespace OHOS