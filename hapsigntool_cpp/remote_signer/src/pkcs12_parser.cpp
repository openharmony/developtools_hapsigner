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
#include "pkcs12_parser.h"

namespace OHOS {
namespace SignatureTools {

static constexpr int BUFFER_SIZE = 4096;

PKCS12Parser::PKCS12Parser(const std::string& storePath)
{
    this->p12=Init(storePath);
}

PKCS12Parser::~PKCS12Parser()
{
    PKCS12_free(this->p12);
    this->p12 = NULL;
}

// fName utf-8 format: string
static int compare(const std::string& friendName, ASN1_STRING* fName)
{
    int result = -1;
    if (fName == NULL || friendName.empty()) {
        return 0;
    }
    int len = -1;
    unsigned char* data = NULL;
    len = ASN1_STRING_to_UTF8(&data, fName);
    if (len >= 0 && friendName == std::string(reinterpret_cast<char*>(data), len)) {
        result = 0;
    }
    OPENSSL_free(data);
    return result;
}

bool PKCS12Parser::ParseSafeBag(PKCS12_SAFEBAG* bag, const char* pkeyPassword, int passLen, EVP_PKEY** outPkey,
                              STACK_OF(X509)* outCerts)
{
    ASN1_BMPSTRING* friendlyName = NULL;
    ASN1_OCTET_STRING* localKeyID = NULL;
    const ASN1_TYPE* attr = PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName);
    if (attr) {
        friendlyName = attr->value.bmpstring;
    }
    
    if (friendlyName == NULL || compare(this->friendName, friendlyName) != 0) {
        return true;
    }
    attr = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID);
    if (attr) {
        localKeyID = attr->value.octet_string;
    }

    PKCS8_PRIV_KEY_INFO* pkcs8;
    int nid = PKCS12_SAFEBAG_get_nid(bag);
    if (nid == NID_keyBag) {
        if (outPkey || *outPkey) {
            return true;
        }
        *outPkey = EVP_PKCS82PKEY(PKCS12_SAFEBAG_get0_p8inf(bag));
        if (*outPkey == NULL) {
            goto err;
        }
    } else if (nid == NID_pkcs8ShroudedKeyBag) {
        if (outPkey == NULL || *outPkey) {
            return true;
        }
        pkcs8 = PKCS12_decrypt_skey(bag, pkeyPassword, passLen);
        if (pkcs8 == NULL) {
            goto err;
        }
        *outPkey = EVP_PKCS82PKEY(pkcs8);
        PKCS8_PRIV_KEY_INFO_free(pkcs8);
        if (!(*outPkey)) {
            goto err;
        }
    }
    return true;
err:
    return false;
}

bool PKCS12Parser::ParseSafeBags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* pass, int passLen,
                                 EVP_PKEY** outPkey, STACK_OF(X509)* outCerts)
{
    int safeBagNums = sk_PKCS12_SAFEBAG_num(bags);
    for (int i = 0; i < safeBagNums; i++) {
        PKCS12_SAFEBAG*safeBag=sk_PKCS12_SAFEBAG_value(bags, i);
        if (ParseSafeBag(safeBag, pass, passLen, outPkey, outCerts) == false) {
            return false;
        }
    }
    return true;
}

bool PKCS12Parser::ParsePkcs12(const char* storePassword, const char* keyPassword,
                               EVP_PKEY** outPrivateKey, STACK_OF(X509)* outCerts)
{
    STACK_OF(PKCS7)* authsafes = PKCS12_unpack_authsafes(this->p12);
    if (authsafes == NULL) {
        return false;
    }
    int authsafesNum = sk_PKCS7_num(authsafes);
    for (int i = 0; i < authsafesNum; i++) {
        PKCS7*p7 = sk_PKCS7_value(authsafes, i);
        STACK_OF(PKCS12_SAFEBAG)* safebags = NULL;
        int bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            safebags = PKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            safebags = PKCS12_unpack_p7encdata(p7, storePassword, -1);
        } else {
            continue;
        }
        if (!safebags) {
            sk_PKCS7_pop_free(authsafes, PKCS7_free);
            return false;
        }
        if (!ParseSafeBags(safebags, keyPassword, -1, outPrivateKey, outCerts)) {
            sk_PKCS12_SAFEBAG_pop_free(safebags, PKCS12_SAFEBAG_free);
            sk_PKCS7_pop_free(authsafes, PKCS7_free);
            return false;
        }
        sk_PKCS12_SAFEBAG_pop_free(safebags, PKCS12_SAFEBAG_free);
    }
    sk_PKCS7_pop_free(authsafes, PKCS7_free);
    return true;
}

bool PKCS12Parser::ParsePrepare(const char* fName, const char** pstorePass, const char* keyPass,
                                EVP_PKEY** outPrivateKey, X509** outCert, STACK_OF(X509)** outCertchain,
                                STACK_OF(X509)** poutCerts)
{
    this->friendName = fName;

    if (outPrivateKey) {
        *outPrivateKey = NULL;
    }
    if (outCert) {
        *outCert = NULL;
    }

    if (!this->p12) {
        return false;
    }


    if (!*pstorePass || !**pstorePass) {
        if (PKCS12_verify_mac(this->p12, NULL, 0)) {
            *pstorePass = NULL;
        }
        else if (PKCS12_verify_mac(this->p12, "", 0)) {
            *pstorePass = "";
        }
        else {
            goto err;
        }
    }
    else if (!PKCS12_verify_mac(this->p12, *pstorePass, -1)) {
        goto err;
    }

    *poutCerts = sk_X509_new_null();

    if (!*poutCerts) {
        goto err;
    }

    if (!ParsePkcs12(*pstorePass, keyPass, outPrivateKey, *poutCerts)) {
        goto err;
    }
    return true;
err:
    return false;
}

bool PKCS12Parser::Parse(const char* fName, const char* storePass, const char* keyPass, EVP_PKEY** outPrivateKey,
                                 X509** outCert, STACK_OF(X509)** outCertchain)
{
    STACK_OF(X509)* outCerts = NULL;
    X509* cert = NULL;
    if (!ParsePrepare(fName, &storePass, keyPass, outPrivateKey, outCert, outCertchain, &outCerts)) {
        goto err;
    }
    while ((cert = sk_X509_pop(outCerts))) {
        if (outPrivateKey && *outPrivateKey && outCert && !*outCert) {
            ERR_set_mark();
            if (X509_check_private_key(cert, *outPrivateKey)) {
                *outCert = cert;
                cert = NULL;
            }
            ERR_pop_to_mark();
        }

        if (outCertchain && cert) {
            if (!*outCertchain) {
                *outCertchain = sk_X509_new_null();
            }
            if (!*outCertchain) {
                goto err;
            }
            if (!sk_X509_push(*outCertchain, cert)) {
                goto err;
            }
            cert = NULL;
        }
        X509_free(cert);
    }

    sk_X509_pop_free(outCerts, X509_free);

    return true;

err:
    if (outPrivateKey) {
        EVP_PKEY_free(*outPrivateKey);
        *outPrivateKey = NULL;
    }
    if (outCert) {
        X509_free(*outCert);
        *outCert = NULL;
    }
    X509_free(cert);
    sk_X509_pop_free(outCerts, X509_free);
    return false;
}

PKCS12* PKCS12Parser::Init(const std::string& path)
{
    std::string p12Content;
    std::ifstream in(path, std::ios::binary);
    char buf[BUFFER_SIZE];
    while (in) {
        in.read(buf, sizeof(buf));
        p12Content.append(buf, in.gcount());
    }
    if (p12Content.empty()) {
        std::cout << "empty p12 file" << std::endl;
        return NULL;
    }
    const unsigned char* data = reinterpret_cast<const unsigned char*>(p12Content.data());
    PKCS12* p12 = d2i_PKCS12(NULL, &data, static_cast<long>(p12Content.size()));
    if (p12 == NULL) {
        std::cout << "serialize pkcs12 failed" << std::endl;
        return NULL;
    }
    return p12;
}
} // namespace SignatureTools
} // namespace OHOS