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
#include "key_store_helper.h"
#include <cstring>
#include "openssl/err.h"
#include "constant.h"
#include "signature_tools_errno.h"

namespace OHOS {
namespace SignatureTools {
KeyStoreHelper::KeyStoreHelper()
{
    this->passWordStatus = true;
    this->keyPairPwdLen = 0;
    this->keyStorePwdLen = 0;
    this->publicKeyStatus = RET_FAILED;
    this->privateKeyStatus = RET_FAILED;
}

void KeyStoreHelper::SetPassWordStatus(bool status)
{
    this->passWordStatus = status;
}

bool KeyStoreHelper::GetPassWordStatus()
{
    return this->passWordStatus;
}

void KeyStoreHelper::ResetKeyStatusvariable()
{
    this->publicKeyStatus = RET_FAILED;
    this->privateKeyStatus = RET_FAILED;
}

void KeyStoreHelper::ResePwdLenvariable()
{
    this->keyPairPwdLen = 0;
    this->keyStorePwdLen = 0;
}

void KeyStoreHelper::KeyPairFree(EC_GROUP* group, EC_KEY* pkey, const std::string& Message)
{
    if (!Message.empty()) {
        SIGNATURE_TOOLS_LOGE("%{public}s", Message.c_str());
    }

    EC_GROUP_free(group);
    group = nullptr;

    EC_KEY_free(pkey);
    pkey = nullptr;
}

void KeyStoreHelper::KeyPairFree(BIGNUM* bnSerial, X509_NAME* issuerName, X509_NAME* subjectName,
                                 ASN1_INTEGER* ai, const std::string& Message)
{
    if (!Message.empty()) {
        SIGNATURE_TOOLS_LOGE("%{public}s", Message.c_str());
    }

    BN_free(bnSerial);
    bnSerial = nullptr;

    ASN1_INTEGER_free(ai);
    ai = nullptr;

    X509_NAME_free(issuerName);
    issuerName = nullptr;

    X509_NAME_free(subjectName);
    subjectName = nullptr;
}

void KeyStoreHelper::KeyPairFree(X509* cert, PKCS12* p12, BIO* bioOut, const std::string& Message)
{
    if (!Message.empty()) {
        SIGNATURE_TOOLS_LOGE("%{public}s", Message.c_str());
    }

    X509_free(cert);
    cert = nullptr;

    PKCS12_free(p12);
    p12 = nullptr;

    BIO_free_all(bioOut);
    bioOut = nullptr;
}

void KeyStoreHelper::KeyPairFree(STACK_OF(X509)* ocerts, STACK_OF(PKCS12_SAFEBAG)* bags, char* name)
{
    sk_X509_pop_free(ocerts, X509_free);
    ocerts = nullptr;

    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    bags = nullptr;

    free(name);
    name = nullptr;
}

void KeyStoreHelper::KeyPairFree(STACK_OF(PKCS7)* safes, EVP_PKEY* publickey)
{
    sk_PKCS7_pop_free(safes, PKCS7_free);
    safes = nullptr;

    EVP_PKEY_free(publickey);
    publickey = nullptr;
}

void KeyStoreHelper::KeyPairFree(STACK_OF(PKCS12_SAFEBAG)* bags, PKCS8_PRIV_KEY_INFO* p8,
                                 char* name, const std::string& Message)
{
    if (!Message.empty()) {
        SIGNATURE_TOOLS_LOGE("%{public}s", Message.c_str());
    }

    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    bags = nullptr;

    PKCS8_PRIV_KEY_INFO_free(p8);
    p8 = nullptr;

    free(name);
    name = nullptr;
}

bool KeyStoreHelper::InitX509(X509& cert, EVP_PKEY& evpPkey)
{
    BIGNUM* bnSerial = BN_new();
    X509_NAME* issuerName = X509_NAME_new();
    const EVP_MD* md = EVP_sha256();
    X509_NAME* subjectName = nullptr;
    ASN1_INTEGER* ai = BN_to_ASN1_INTEGER(bnSerial, NULL);
    if (ai == NULL || issuerName == NULL) {
        this->KeyPairFree(bnSerial, issuerName, subjectName, ai,
                          "Failed to initialize the x509 structure.");
        return false;
    }

    X509_set_serialNumber(&cert, ai);
    X509_gmtime_adj(X509_get_notBefore(&cert), 0);
    X509_gmtime_adj(X509_get_notAfter(&cert), (long)DEFAULT_VALIDITY_DAYS * ONE_DAY_TIME);
    if (!X509_NAME_add_entry_by_txt(issuerName, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0)
        || !X509_NAME_add_entry_by_txt(issuerName, "O", MBSTRING_ASC, (unsigned char*)"My Company", -1, -1, 0)
        || !X509_NAME_add_entry_by_txt(issuerName, "CN", MBSTRING_ASC, (unsigned char*)"My Issuer", -1, -1, 0)) {
        this->KeyPairFree(bnSerial, issuerName, subjectName, ai,
                          "Failed to initialize the x509 structure.X509_NAME type");
        return false;
    }

    X509_set_issuer_name(&cert, issuerName);
    subjectName = X509_NAME_dup(issuerName);
    if (subjectName == NULL) {
        this->KeyPairFree(bnSerial, issuerName, subjectName, ai,
                          "Failed to initialize the x509 structure.X509_NAME type");
        return false;
    }

    X509_set_subject_name(&cert, subjectName);
    if (!X509_set_pubkey(&cert, &evpPkey)) {
        this->KeyPairFree(bnSerial, issuerName, subjectName, ai,
                          "Failed to initialize the x509 structure.X509_NAME type");
        return false;
    }

    X509_set_version(&cert, DEFAULT_CERT_VERSION);
    if (!X509_sign(&cert, &evpPkey, md)) {
        this->KeyPairFree(bnSerial, issuerName, subjectName, ai,
                          "Failed to initialize the x509 structure.X509_NAME type");
        return false;
    }

    this->KeyPairFree(bnSerial, issuerName, subjectName, ai, "");
    return true;
}

int KeyStoreHelper::FindFriendlyName(PKCS12* p12, const char* alias, char* keyPass,
                                     char* pass, EVP_PKEY** keyPiar)
{
    EVP_PKEY* publickey = nullptr;
    STACK_OF(PKCS7)* safes = nullptr;
    PKCS7* safe = nullptr;
    int n;

    this->ResePwdLenvariable();
    this->ResetKeyStatusvariable();

    if (pass != nullptr)
        this->keyStorePwdLen = strlen(pass);

    if (keyPass != nullptr)
        this->keyPairPwdLen = strlen(keyPass);

    if ((safes = PKCS12_unpack_authsafes(p12)) == NULL) {
        sk_PKCS7_pop_free(safes, PKCS7_free);
        return RET_FAILED;
    }

    for (n = 0; n < sk_PKCS7_num(safes); n++) {
        if ((this->publicKeyStatus == RET_OK) && (this->privateKeyStatus == RET_OK))
            break;

        safe = sk_PKCS7_value(safes, n);
        if (OBJ_obj2nid(safe->type) == NID_pkcs7_encrypted) {
            if (this->publicKeyStatus != RET_OK)
                this->publicKeyStatus = this->GetPublicKey(safe, alias, pass, this->keyStorePwdLen, &publickey);

            if (!this->GetPassWordStatus()) {
                this->KeyPairFree(safes, publickey);
                return RET_FAILED;
            }
        } else if (OBJ_obj2nid(safe->type) == NID_pkcs7_data && this->privateKeyStatus != RET_OK) {
            this->privateKeyStatus = this->GetPrivateKey(safe, alias, keyPass, this->keyPairPwdLen, &(*keyPiar));
            if (!this->GetPassWordStatus()) {
                this->KeyPairFree(safes, publickey);
                return RET_FAILED;
            }
        }
    }

    if (((this->publicKeyStatus == RET_OK) && (this->privateKeyStatus == RET_OK))
        && (publickey != nullptr) && (*keyPiar != nullptr)) {
        if (EVP_PKEY_copy_parameters(*keyPiar, publickey) != 1) {
            this->KeyPairFree(safes, publickey);
            return RET_FAILED;
        }

        this->KeyPairFree(safes, publickey);
        return RET_OK;
    }

    this->KeyPairFree(safes, publickey);
    return RET_FAILED;
}

int KeyStoreHelper::GetPublicKey(PKCS7* safe, const char* alias, char* pass, int passlen, EVP_PKEY** publickey)
{
    char* name = NULL;
    PKCS12_SAFEBAG* bag = nullptr;
    STACK_OF(PKCS12_SAFEBAG)* bags = nullptr;
    STACK_OF(X509)* ocerts = sk_X509_new_null();

    bags = PKCS12_unpack_p7encdata(safe, pass, passlen);
    if (bags == nullptr) {
        PrintErrorNumberMsg("KEY_ERROR", KEY_ERROR, "keypair password error");
        KeyPairFree(ocerts, bags, name);
        SetPassWordStatus(false);
        return RET_FAILED;
    }

    if (this->ParseBags(bags, pass, passlen, ocerts) == RET_FAILED) {
        PrintErrorNumberMsg("KEY_ERROR", KEY_ERROR, "keypair password error");
        KeyPairFree(ocerts, bags, name);
        SetPassWordStatus(false);
        return RET_FAILED;
    }
    for (int i = 0; i < sk_X509_num(ocerts); i++) {
        bag = sk_PKCS12_SAFEBAG_value(bags, i);
        name = PKCS12_get_friendlyname(bag);
        if (strcmp(name, alias) != 0)
            continue;
        X509* cert = sk_X509_value(ocerts, i);
        if (cert == nullptr) {
            KeyPairFree(ocerts, bags, name);
            return RET_FAILED;
        }
        *publickey = X509_get_pubkey(cert);
        if (*publickey != nullptr) {
            KeyPairFree(ocerts, bags, name);
            return RET_OK;
        }
    }

    KeyPairFree(ocerts, bags, name);
    return RET_FAILED;
}

int KeyStoreHelper::GetPrivateKey(PKCS7* safe, const char* alias, char* pass, int passlen, EVP_PKEY** keyPiar)
{
    STACK_OF(PKCS12_SAFEBAG)* bags = nullptr;
    PKCS12_SAFEBAG* bag = nullptr;
    PKCS8_PRIV_KEY_INFO* p8 = nullptr;
    char* name = NULL;

    bags = PKCS12_unpack_p7data(safe);
    for (int m = 0; m < sk_PKCS12_SAFEBAG_num(bags); m++) {
        bag = sk_PKCS12_SAFEBAG_value(bags, m);
        if (PKCS12_SAFEBAG_get_nid(bag) != NID_pkcs8ShroudedKeyBag) {
            continue;
        }
        name = PKCS12_get_friendlyname(bag);
        if (strcmp(name, alias) != 0) {
            continue;
        }
        if ((p8 = PKCS12_decrypt_skey(bag, pass, passlen)) == NULL) {
            PrintErrorNumberMsg("KEY_ERROR", KEY_ERROR, "keypair password error");
            KeyPairFree(bags, p8, name, "keypair password error");
            this->SetPassWordStatus(false);
            return RET_FAILED;
        }
        *keyPiar = EVP_PKCS82PKEY(p8);
        if (*keyPiar == NULL) {
            KeyPairFree(bags, p8, name, "keypair password error");
            return RET_FAILED;
        }

        KeyPairFree(bags, p8, name, "");
        return RET_OK;
    }

    KeyPairFree(bags, p8, name, "");
    return RET_FAILED;
}


int KeyStoreHelper::Store(EVP_PKEY* evpPkey, std::string& keyStorePath,
                          char* storePwd, std::string alias, char* keyPwd)
{
    X509* cert = X509_new();
    PKCS12* p12 = nullptr;
    BIO* bioOut = nullptr;

    if (evpPkey == nullptr) {
        KeyPairFree(cert, p12, bioOut, "The key pair pointer is null");
        return RET_FAILED;
    }

    if (!this->InitX509(*cert, *evpPkey)) {
        KeyPairFree(cert, p12, bioOut, "initialize x509 structure failed");
        return RET_FAILED;
    }

    if (CreatePKCS12(&p12, keyStorePath.c_str(), storePwd, keyPwd, alias.c_str(), evpPkey, cert) == RET_FAILED) {
        KeyPairFree(cert, p12, bioOut, "Create PKCS12 Structure Failed");
        return RET_FAILED;
    }

    bioOut = BIO_new_file(keyStorePath.c_str(), "wb");
    if (bioOut == nullptr) {
        std::string str = "Open keyStore file failed";
        str = str + keyStorePath;
        KeyPairFree(cert, p12, bioOut, str);
        return RET_FAILED;
    }

    if (i2d_PKCS12_bio(bioOut, p12) != 1) {
        KeyPairFree(cert, p12, bioOut, "PKCS12 structure write File failure");
        return RET_FAILED;
    }

    KeyPairFree(cert, p12, bioOut, "");
    return RET_OK;
}

int KeyStoreHelper::CreatePKCS12(PKCS12** p12, const char* charsStorePath, char* storePwd,
                                 char* keyPwd, const char* charsAlias, EVP_PKEY* evpPkey, X509* cert)
{
    STACK_OF(PKCS7)* safes = nullptr;
    PKCS12* acceptP12 = nullptr;
    BIO* bioOut = BIO_new_file(charsStorePath, "rb");
    if (bioOut != nullptr) {
        acceptP12 = d2i_PKCS12_bio(bioOut, NULL);
        if (acceptP12 == nullptr) {
            return RET_FAILED;
        }
        if (Pkcs12Parse(acceptP12, storePwd) == RET_FAILED) {
            PrintErrorNumberMsg("KEY_ERROR", KEY_ERROR, "keyStore password error");
            BIO_free_all(bioOut);
            return RET_FAILED;
        }
        safes = PKCS12_unpack_authsafes(acceptP12);
    }

    BIO_free_all(bioOut);
    if (storePwd == nullptr) {
        *p12 = Pkcs12Create(storePwd, keyPwd, charsAlias, evpPkey, cert, 0, 0, 0, -1, 0, &safes);
    } else {
        *p12 = Pkcs12Create(storePwd, keyPwd, charsAlias, evpPkey, cert, 0, 0, 0, 0, 0, &safes);
    }

    sk_PKCS7_pop_free(safes, PKCS7_free);
    safes = nullptr;
    PKCS12_free(acceptP12);

    if (*p12 == nullptr) {
        return RET_FAILED;
    }
    return RET_OK;
}

int KeyStoreHelper::ReadStore(std::string keyStorePath, char* storePwd, const std::string& alias,
                              char* keyPwd, EVP_PKEY** evpPkey)
{
    X509* cert = nullptr;
    PKCS12* p12 = nullptr;
    BIO* bioOut = nullptr;

    bioOut = BIO_new_file(keyStorePath.c_str(), "rb");
    if (bioOut == nullptr) {
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        std::string str = "Open keyStor file failed";
        str = str + keyStorePath;
        this->KeyPairFree(cert, p12, bioOut, str);
        return RET_FAILED;
    }

    p12 = d2i_PKCS12_bio(bioOut, NULL);
    if (this->Pkcs12Parse(p12, storePwd) == RET_FAILED) {
        this->KeyPairFree(cert, p12, bioOut, "");
        PrintErrorNumberMsg("KEY_ERROR", KEY_ERROR, "keyStore password error");
        this->SetPassWordStatus(false);
        return RET_FAILED;
    }
    int status = this->FindFriendlyName(p12, alias.c_str(), keyPwd, storePwd, &(*evpPkey));
    if (status == RET_FAILED) {
        this->KeyPairFree(cert, p12, bioOut, "");
        return RET_FAILED;
    }

    this->KeyPairFree(cert, p12, bioOut, "");
    return RET_OK;
}

int KeyStoreHelper::Pkcs12Parse(PKCS12* p12, const char* pass)
{
    if (p12 == NULL) {
        SIGNATURE_TOOLS_LOGE("p12 structure nullptr");
        return RET_FAILED;
    }

    if (pass == NULL || *pass == '\0') {
        if (!PKCS12_mac_present(p12)
            || PKCS12_verify_mac(p12, NULL, 0))
            pass = NULL;
        else if (PKCS12_verify_mac(p12, "", 0))
            pass = "";
        else {
            SIGNATURE_TOOLS_LOGE("Password format error");
            return RET_FAILED;
        }
    } else if (!PKCS12_verify_mac(p12, pass, -1)) {
        SIGNATURE_TOOLS_LOGE("The keystore password does not match");
        return RET_FAILED;
    }

    return RET_OK;
}

bool KeyStoreHelper::IsKeyStoreFileExist(std::string& keyStorePath)
{
    if (keyStorePath.empty()) {
        return false;
    }
    BIO* bioOut = nullptr;
    bioOut = BIO_new_file(keyStorePath.c_str(), "rb");
    if (bioOut == nullptr) {
        return false;
    }
    BIO_free(bioOut);
    return true;
}

EVP_PKEY* KeyStoreHelper::GenerateKeyPair(const std::string& algorithm, int keySize)
{
    if (algorithm.empty() || (0 == keySize)) {
        SIGNATURE_TOOLS_LOGI("keyAlg and keySize is nullptr!");
        return nullptr;
    }
    EC_GROUP* group = nullptr;
    EC_KEY* keyPair = EC_KEY_new();

    if (keySize == static_cast<int>(NIST_P_256)) {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else if (keySize == static_cast<int>(NIST_P_384)) {
        group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    } else {
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        this->KeyPairFree(group, keyPair, "Algorithm length error");
        return nullptr;
    }
    if (!group) {
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        this->KeyPairFree(group, keyPair, "Elliptic curve encryption using P256 or P384 failed");
        return nullptr;
    }

    EC_KEY_set_group(keyPair, group);
    if (EC_KEY_generate_key(keyPair) != 1) {
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        this->KeyPairFree(group, keyPair, "Description Failed to generate an elliptic curve key pair");
        return nullptr;
    }
    if (EC_KEY_check_key(keyPair) != 1) {
        VerifyHapOpensslUtils::GetOpensslErrorMessage();
        this->KeyPairFree(group, keyPair, "Description Failed to generate an elliptic curve key pair");
        return nullptr;
    }
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, keyPair);
    this->KeyPairFree(group, keyPair, "");
    return pkey;
}

PKCS12* KeyStoreHelper::Pkcs12Create(const char* pass, const char* keyPass, const char* name, EVP_PKEY* pkey,
                                     X509* cert, int nid_key, int nid_cert, int iter,
                                     int mac_iter, int keytype, STACK_OF(PKCS7)** safes)
{
    PKCS12* p12 = NULL;
    STACK_OF(PKCS12_SAFEBAG)* bags = NULL;
    unsigned char keyid[EVP_MAX_MD_SIZE];
    unsigned int keyidlen = 0;
    PKCS12_SAFEBAG* bag = NULL;

    if (!nid_cert)
        nid_cert = NID_PBE_CBC;
    this->SetNidMac(nid_key, iter, mac_iter);
    if (!pkey && !cert) {
        PKCS12err(PKCS12_F_PKCS12_CREATE, PKCS12_R_INVALID_NULL_ARGUMENT);
        return NULL;
    }

    if (!X509_check_private_key(cert, pkey))
        return NULL;
    X509_digest(cert, EVP_sha384(), keyid, &keyidlen);

    if (SetCertPkcs12(cert, bag, bags, keyid, keyidlen, name, safes, nid_cert, iter, pass) == RET_FAILED)
        goto err;

    if (SetPkeyPkcs12(pkey, bag, bags, name, safes, iter, keyPass, keytype, nid_key, keyid, keyidlen) == RET_FAILED)
        goto err;

    p12 = PKCS12_add_safes(*safes, 0);

    if (!p12)
        goto err;
    safes = NULL;
    if ((mac_iter != -1) &&
        !PKCS12_set_mac(p12, pass, -1, NULL, 0, mac_iter, NULL))
        goto err;
    return p12;

err:
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    return NULL;
}

void KeyStoreHelper::SetNidMac(int& nid_key, int& iter, int& mac_iter)
{
    if (!nid_key)
        nid_key = NID_TRIPLEDES_CBC;
    if (!iter)
        iter = PKCS12_DEFAULT_ITER;
    if (!mac_iter)
        mac_iter = 1;
}

int KeyStoreHelper::SetCertPkcs12(X509* cert, PKCS12_SAFEBAG* bag, STACK_OF(PKCS12_SAFEBAG)* bags,
                                  unsigned char* keyid, unsigned int keyidlen,
                                  const char* name, STACK_OF(PKCS7)** safes,
                                  int nid_cert, int iter, const char* pass)
{
    if (cert) {
        bag = PKCS12_add_cert(&bags, cert);
        if (name && !PKCS12_add_friendlyname(bag, name, -1)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            bags = NULL;
            return RET_FAILED;
        }

        if (keyidlen && !PKCS12_add_localkeyid(bag, keyid, keyidlen)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            bags = NULL;
            return RET_FAILED;
        }
    }

    if (bags && !PKCS12_add_safe(safes, bags, nid_cert, iter, pass)) {
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        bags = NULL;
        return RET_FAILED;
    }

    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    bags = NULL;
    return RET_OK;
}

int KeyStoreHelper::SetPkeyPkcs12(EVP_PKEY* pkey, PKCS12_SAFEBAG* bag, STACK_OF(PKCS12_SAFEBAG)* bags,
                                  const char* name, STACK_OF(PKCS7)** safes, int iter, const char* keyPass,
                                  int keytype, int nid_key, unsigned char* keyid, unsigned int keyidlen)
{
    if (pkey) {
        bag = PKCS12_add_key(&bags, pkey, keytype, iter, nid_key, keyPass);
        if (!bag)
            return RET_FAILED;

        if (this->CopyBagAttr(bag, pkey, NID_ms_csp_name) == RET_FAILED) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            bags = NULL;
            return RET_FAILED;
        }

        if (this->CopyBagAttr(bag, pkey, NID_LocalKeySet) == RET_FAILED) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            bags = NULL;
            return RET_FAILED;
        }

        if (name && !PKCS12_add_friendlyname(bag, name, -1)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            bags = NULL;
            return RET_FAILED;
        }

        if (keyidlen && !PKCS12_add_localkeyid(bag, keyid, keyidlen)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            bags = NULL;
            return RET_FAILED;
        }
    }
    if (bags && !PKCS12_add_safe(safes, bags, -1, 0, NULL)) {
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        bags = NULL;
        return RET_FAILED;
    }

    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    bags = NULL;
    return RET_OK;
}

int KeyStoreHelper::CopyBagAttr(PKCS12_SAFEBAG* bag, EVP_PKEY* pkey, int nid)
{
    int idx;
    X509_ATTRIBUTE* attr;
    idx = EVP_PKEY_get_attr_by_NID(pkey, nid, -1);
    if (idx < 0)
        return RET_OK;
    attr = EVP_PKEY_get_attr(pkey, idx);
    STACK_OF(X509_ATTRIBUTE)* attrlib = const_cast<STACK_OF(X509_ATTRIBUTE)*>(PKCS12_SAFEBAG_get0_attrs(bag));
    if (!X509at_add1_attr(&attrlib, attr))
        return RET_FAILED;
    return RET_OK;
}

int KeyStoreHelper::ParseBag(PKCS12_SAFEBAG* bag, const char* pass, int passlen, STACK_OF(X509)* ocerts)
{
    X509* x509 = nullptr;
    const ASN1_TYPE* attrib;
    ASN1_BMPSTRING* fname = NULL;
    ASN1_OCTET_STRING* lkid = NULL;
    if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName)))
        fname = attrib->value.bmpstring;

    if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID)))
        lkid = attrib->value.octet_string;

    if (PKCS12_SAFEBAG_get_nid(bag) != NID_certBag && PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate) {
        return RET_OK;
    }

    if ((x509 = PKCS12_SAFEBAG_get1_cert(bag)) == NULL)
        return RET_FAILED;

    if (lkid && !X509_keyid_set1(x509, lkid->data, lkid->length)) {
        goto err;
    }

    if (fname) {
        int len;
        unsigned char* data;
        len = ASN1_STRING_to_UTF8(&data, fname);
        if (!X509AliasSet1(len, x509, data)) {
            goto err;
        }
    }
    if (!sk_X509_push(ocerts, x509)) {
        goto err;
    }

    return RET_OK;
err:
    X509_free(x509);
    return RET_FAILED;
}

bool KeyStoreHelper::X509AliasSet1(int len, X509* x509, unsigned char* data)
{
    int r;
    if (len >= 0) {
        r = X509_alias_set1(x509, data, len);
        OPENSSL_free(data);
        if (!r) {
            X509_free(x509);
            return false;
        }
    }
    return true;
}

int KeyStoreHelper::ParseBags(const STACK_OF(PKCS12_SAFEBAG)* bags, const char* pass,
                              int passlen, STACK_OF(X509)* ocerts)
{
    int i;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (this->ParseBag(sk_PKCS12_SAFEBAG_value(bags, i), pass, passlen, ocerts) == RET_FAILED)
            return RET_FAILED;
    }
    return RET_OK;
}
} // namespace SignatureTools
} // namespace OHOS