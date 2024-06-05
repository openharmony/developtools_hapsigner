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
#include "key_store_helper.h"
#include "openssl/err.h"
#include "p12_local.h"
#include "constant.h"
#include <cstring>
#include "signature_tools_errno.h"

#define VERSIONS 2
#define SECONDS 60
#define MINUTES 60
#define HOURS 24
#define DAYS 30
#define NID_PBE_CBC 149
#define NID_TRIPLEDES_CBC 146
#define PATH_SIZE 100

using namespace OHOS::SignatureTools;

bool KeyStoreHelper::InitX509(X509& cert, EVP_PKEY& evpPkey)
{
    BIGNUM* bnSerial = BN_new();
    X509_NAME* issuerName = X509_NAME_new();
    const EVP_MD* md = EVP_sha256();
    X509_NAME* subjectName = nullptr;
    ASN1_INTEGER* ai = BN_to_ASN1_INTEGER(bnSerial, NULL);
    if (ai == NULL)
        goto err;

    X509_set_serialNumber(&cert, ai);
    X509_gmtime_adj(X509_get_notBefore(&cert), 0);
    X509_gmtime_adj(X509_get_notAfter(&cert), (long)SECONDS * SECONDS * HOURS * DAYS);
    if (issuerName == NULL)
        goto err;

    if (!X509_NAME_add_entry_by_txt(issuerName, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0))
        goto err;

    if (!X509_NAME_add_entry_by_txt(issuerName, "O", MBSTRING_ASC, (unsigned char*)"My Company", -1, -1, 0))
        goto err;

    if (!X509_NAME_add_entry_by_txt(issuerName, "CN", MBSTRING_ASC, (unsigned char*)"My Issuer", -1, -1, 0))
        goto err;

    X509_set_issuer_name(&cert, issuerName);
    subjectName = X509_NAME_dup(issuerName);
    if (subjectName == NULL)
        goto err;

    X509_set_subject_name(&cert, subjectName);
    if (!X509_set_pubkey(&cert, &evpPkey))
        goto err;

    X509_set_version(&cert, VERSIONS);
    if (!X509_sign(&cert, &evpPkey, md))
        goto err;

    BN_free(bnSerial);
    ASN1_INTEGER_free(ai);
    X509_NAME_free(issuerName);
    X509_NAME_free(subjectName);
    return true;
err:
    SIGNATURE_TOOLS_LOGE("Failed to initialize the x509 structure!");
    BN_free(bnSerial);
    ASN1_INTEGER_free(ai);
    X509_NAME_free(issuerName);
    X509_NAME_free(subjectName);

    return false;
}

void KeyStoreHelper::StringToChars(std::string& str, char* chars)
{
    size_t size = str.size();
    for (size_t i = 0; i < size; i++) {
        chars[i] = str.at(i);
    }
}

static int FreeFindFriendlyName(STACK_OF(PKCS7)* safes, EVP_PKEY* publickey, int status)
{
    sk_PKCS7_pop_free(safes, PKCS7_free);
    EVP_PKEY_free(publickey);

    return status;
}

int KeyStoreHelper::FindFriendlyName(PKCS12* p12, char* alias, char* keyPass,
                                     char* pass, EVP_PKEY** keyPiar)
{
    STACK_OF(PKCS7)* safes;
    PKCS7* safe;
    int n;
    int passlen1;
    int passlen2;
    int status1;
    int status2;
    passlen1 = passlen2 = 0;
    status1 = status2 = -1;
    if (pass != nullptr)
        passlen1 = strlen(pass);

    if (keyPass != nullptr)
        passlen2 = strlen(keyPass);

    if ((safes = PKCS12_unpack_authsafes(p12)) == NULL) {
        sk_PKCS7_pop_free(safes, PKCS7_free);
        return RET_FAILED;
    }
   
    EVP_PKEY* publickey = nullptr;
    for (n = 0; n < sk_PKCS7_num(safes); n++) {
        if ((status1 == RET_OK) && (status2 == RET_OK))
            break;
        safe = sk_PKCS7_value(safes, n);
        if (OBJ_obj2nid(safe->type) == NID_pkcs7_encrypted) {
            if (status1 != RET_OK)
                status1 = this->GetPublicKey(safe, alias, pass, passlen1, &publickey);

            if (status1 == RET_PASS_ERROR) {
                return FreeFindFriendlyName(safes, publickey, RET_PASS_ERROR);
            }
        } else if (OBJ_obj2nid(safe->type) == NID_pkcs7_data && status2 != RET_OK) {
            status2 = this->GetPrivateKey(safe, alias, keyPass, passlen2, &(*keyPiar));
            if (status2 == RET_PASS_ERROR) {
                return FreeFindFriendlyName(safes, publickey, RET_PASS_ERROR);
            }
        } else
            continue;
    }

    if (((status1 == RET_OK) && (status2 == RET_OK)) && (publickey != nullptr) && (*keyPiar != nullptr)) {
        if (EVP_PKEY_copy_parameters(*keyPiar, publickey) != 1) {
            return FreeFindFriendlyName(safes, publickey, RET_FAILED);
        }

        return FreeFindFriendlyName(safes, publickey, RET_OK);
    }

    return FreeFindFriendlyName(safes, publickey, RET_FAILED);
}

int KeyStoreHelper::GetPublicKey(PKCS7* safe, char* alias, char* pass, int passlen, EVP_PKEY** publickey)
{
    STACK_OF(PKCS12_SAFEBAG)* bags;
    PKCS12_SAFEBAG* bag;
    char* name = NULL;
    EVP_PKEY* keyPiar = EVP_PKEY_new();
    STACK_OF(X509)* ocerts = sk_X509_new_null();

    bags = PKCS12_unpack_p7encdata(safe, pass, passlen);
    if (bags == nullptr) {
        CMD_ERROR_MSG("KEY_ERROR", KEY_ERROR, "keypair password error");
        EVP_PKEY_free(keyPiar);
        sk_X509_pop_free(ocerts, X509_free);
        return RET_PASS_ERROR;
    }
    for (int m = 0; m < sk_PKCS12_SAFEBAG_num(bags); m++) {
        bag = sk_PKCS12_SAFEBAG_value(bags, m);
        name = PKCS12_get_friendlyname(bag);
        if (strcmp(name, alias) != 0) {
            continue;
        }
        if (!bags) {
            EVP_PKEY_free(keyPiar);
            sk_X509_pop_free(ocerts, X509_free);
            free(name);
            return RET_FAILED;
        }
        if (this->ParseBags(bags, pass, passlen, &keyPiar, ocerts) == RET_FAILED) {
            CMD_ERROR_MSG("KEY_ERROR", KEY_ERROR, "keypair password error");
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            EVP_PKEY_free(keyPiar);
            sk_X509_pop_free(ocerts, X509_free);
            free(name);
            return RET_PASS_ERROR;
        }
        *publickey = this->CheckAlias(ocerts, bags, bag, alias);
        if (*publickey != nullptr) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            EVP_PKEY_free(keyPiar);
            sk_X509_pop_free(ocerts, X509_free);
            free(name);
            return RET_OK;
        }
    }
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    EVP_PKEY_free(keyPiar);
    sk_X509_pop_free(ocerts, X509_free);
    free(name);
    return RET_FAILED;
}

EVP_PKEY* KeyStoreHelper::CheckAlias(STACK_OF(X509)* ocerts, STACK_OF(PKCS12_SAFEBAG)* bags,
                                     PKCS12_SAFEBAG* bag, char* alias)
{
    char* name = NULL;
    EVP_PKEY* publickey = nullptr;
    for (int i = 0; i < sk_X509_num(ocerts); i++) {
        bag = sk_PKCS12_SAFEBAG_value(bags, i);
        name = PKCS12_get_friendlyname(bag);
        if (strcmp(name, alias) == 0) {
            X509* cert = sk_X509_value(ocerts, i);
            if (cert == nullptr) {
                free(name);
                return nullptr;
            }
            publickey = X509_get_pubkey(cert);
            free(name);
            return publickey;
        }
    }
    free(name);
    return publickey;
}

int KeyStoreHelper::GetPrivateKey(PKCS7* safe, char* alias, char* pass, int passlen, EVP_PKEY** keyPiar)
{
    STACK_OF(PKCS12_SAFEBAG)* bags;
    PKCS12_SAFEBAG* bag;
    PKCS8_PRIV_KEY_INFO* p8;

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
            CMD_ERROR_MSG("KEY_ERROR", KEY_ERROR, "keypair password error");
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            free(name);
            return RET_PASS_ERROR;
        }
        *keyPiar = EVP_PKCS82PKEY(p8);
        if (*keyPiar == NULL) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            PKCS8_PRIV_KEY_INFO_free(p8);
            free(name);
            return RET_FAILED;
        }

        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        PKCS8_PRIV_KEY_INFO_free(p8);
        free(name);
        return RET_OK;
    }

    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    free(name);
    return RET_FAILED;
}


EVP_PKEY* KeyStoreHelper::Store(EVP_PKEY* evpPkey, std::string keyStorePath,
                                char* storePwd, std::string alias, char* keyPwd)
{
    X509* cert = X509_new();
    PKCS12* p12 = nullptr;
    char charsStorePath[PATH_SIZE] = "";
    char charsAlias[PATH_SIZE] = "";
    this->StringToChars(keyStorePath, charsStorePath);
    this->StringToChars(alias, charsAlias);
    if (!this->InitX509(*cert, *evpPkey)) {
        SIGNATURE_TOOLS_LOGE(" initialize x509 structure failed!");
        EVP_PKEY_free(evpPkey);
        X509_free(cert);
        return nullptr;
    }

    p12 = createPKCS12(p12, charsStorePath, storePwd, keyPwd, charsAlias, evpPkey, cert);
    if (p12 == nullptr) {
        SIGNATURE_TOOLS_LOGE("Create PKCS12 Structure Failed !");
        BIONewFileFree(evpPkey, cert, p12);
        return nullptr;
    }
    BIO* bioOut = BIO_new_file(charsStorePath, "wb");
    if (bioOut == nullptr) {
        SIGNATURE_TOOLS_LOGE("Open keyStore file failed, %{public}s", charsStorePath);
        BIONewFileFree(evpPkey, cert, p12);
        return nullptr;
    }
    if (i2d_PKCS12_bio(bioOut, p12) != 1) {
        I2dPkcs12BioFree(evpPkey, cert, p12, bioOut);
        return nullptr;
    }
    X509_free(cert);
    PKCS12_free(p12);
    BIO_free_all(bioOut);
    SIGNATURE_TOOLS_LOGI("keypair write file success");
    return evpPkey;
}

PKCS12* KeyStoreHelper::createPKCS12(PKCS12* p12, char* charsStorePath, char* storePwd,
    char* keyPwd, char* charsAlias, EVP_PKEY* evpPkey, X509* cert)
{
    STACK_OF(PKCS7)* safes = nullptr;
    BIO* bioOut = BIO_new_file(charsStorePath, "rb");
    if (bioOut != nullptr) {
        p12 = d2i_PKCS12_bio(bioOut, NULL);
        if (p12 != nullptr) {
            if (OwnPKCS12_parse(p12, storePwd) == RET_FAILED) {
                CMD_ERROR_MSG("KEY_ERROR", KEY_ERROR, "keyStore password error");
                BIO_free_all(bioOut);
                return nullptr;
            }
            safes = PKCS12_unpack_authsafes(p12);
        }
    }
    BIO_free_all(bioOut);
    if (storePwd == nullptr) {
        p12 = OwnPKCS12_create(storePwd, keyPwd, charsAlias, evpPkey, cert, nullptr, 0, 0, 0, -1, 0, safes);
    } else {
        p12 = OwnPKCS12_create(storePwd, keyPwd, charsAlias, evpPkey, cert, nullptr, 0, 0, 0, 0, 0, safes);
    }

    return p12;
}

void KeyStoreHelper::I2dPkcs12BioFree(EVP_PKEY* evpPkey, X509* cert, PKCS12* p12, BIO* bioOut)
{
    SIGNATURE_TOOLS_LOGE("PKCS12 structure write File failure !");
    EVP_PKEY_free(evpPkey);
    X509_free(cert);
    PKCS12_free(p12);
    BIO_free_all(bioOut);
}

void KeyStoreHelper::BIONewFileFree(EVP_PKEY* evpPkey, X509* cert, PKCS12* p12)
{
    EVP_PKEY_free(evpPkey);
    X509_free(cert);
    PKCS12_free(p12);
}

int KeyStoreHelper::ReadStore(std::string keyStorePath, char* storePwd, std::string alias,
                              char* keyPwd, EVP_PKEY** evpPkey)
{
    char charsStorePath[PATH_SIZE] = "";
    char charsAlias[PATH_SIZE] = "";
    this->StringToChars(keyStorePath, charsStorePath);
    this->StringToChars(alias, charsAlias);
    X509* cert = nullptr;
    PKCS12* p12 = nullptr;
    
    BIO* bioOut = BIO_new_file(charsStorePath, "rb");
    if (bioOut == nullptr) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("Open keyStor file failed, %{public}s", charsStorePath);
        this->ReadStorefailFree(bioOut, p12, cert);

        return RET_FAILED;
    }

    p12 = d2i_PKCS12_bio(bioOut, NULL);
    if (this->OwnPKCS12_parse(p12, storePwd) == RET_FAILED) {
        this->ReadStorefailFree(bioOut, p12, cert);

        CMD_ERROR_MSG("KEY_ERROR", KEY_ERROR, "keyStore password error");
        return RET_PASS_ERROR;
    }
    int status = this->FindFriendlyName(p12, charsAlias, keyPwd, storePwd, &(*evpPkey));
    if (status == RET_PASS_ERROR) {
        this->ReadStorefailFree(bioOut, p12, cert);
        return RET_PASS_ERROR;
    } else if (status == RET_FAILED) {
        this->ReadStorefailFree(bioOut, p12, cert);
        return RET_FAILED;
    }

    this->ReadStorefailFree(bioOut, p12, cert);
    return RET_OK;
}

int KeyStoreHelper::OwnPKCS12_parse(PKCS12* p12, const char* pass)
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

void KeyStoreHelper::ReadStorefailFree(BIO* bioOut, PKCS12* p12, X509* cert)
{
    BIO_free(bioOut);
    PKCS12_free(p12);
    X509_free(cert);
}

bool KeyStoreHelper::GetFileStatus(std::string keyStorePath)
{
    if (keyStorePath.empty()) {
        return false;
    }
    BIO* bioOut = nullptr;
    char charsStorePath[PATH_SIZE] = "";
    this->StringToChars(keyStorePath, charsStorePath);
    bioOut = BIO_new_file(charsStorePath, "rb");
    if (bioOut == nullptr) {
        BIO_free(bioOut);
        return false;
    }
    BIO_free(bioOut);
    return true;
}

EVP_PKEY* KeyStoreHelper::GenerateKeyPair(std::string algorithm, int keySize)
{
    if (algorithm.empty() || (0 == keySize)) {
        SIGNATURE_TOOLS_LOGI("keyAlg and keySize is nullptr!");
        return nullptr;
    }
    EC_GROUP* group = nullptr;
    if (keySize == static_cast<int>(AlgorithmLength::NIST_P_256)) {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    } else if (keySize == static_cast<int>(AlgorithmLength::NIST_P_384)) {
        group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    } else {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("Algorithm length error !");
        return nullptr;
    }
    if (!group) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("Elliptic curve encryption using P256 or P384 failed !");
        EC_GROUP_free(group);
        return nullptr;
    }
    EC_KEY* keyPair = EC_KEY_new();
    EC_KEY_set_group(keyPair, group);
    if (EC_KEY_generate_key(keyPair) != 1) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("Description Failed to generate an elliptic curve key pair !");
        EC_GROUP_free(group);
        EC_KEY_free(keyPair);
        return nullptr;
    }
    if (EC_KEY_check_key(keyPair) != 1) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("Description Failed to generate an elliptic curve key pair !");
        EC_GROUP_free(group);
        EC_KEY_free(keyPair);
        return nullptr;
    }
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, keyPair);
    EC_GROUP_free(group);
    EC_KEY_free(keyPair);
    SIGNATURE_TOOLS_LOGI("key pair is generated succeed !");
    return pkey;
}

PKCS12* KeyStoreHelper::OwnPKCS12_create(const char* pass, const char* keyPass, const char* name, EVP_PKEY* pkey,
                                         X509* cert, STACK_OF(X509)* ca, int nid_key,
                                         int nid_cert, int iter, int mac_iter, int keytype, STACK_OF(PKCS7)* safes)
{
    PKCS12* p12 = NULL;
    STACK_OF(PKCS12_SAFEBAG)* bags = NULL;
    unsigned char keyid[EVP_MAX_MD_SIZE];
    unsigned int keyidlen = 0;
    PKCS12_SAFEBAG* bag = NULL;
    
    if (!nid_cert)
        nid_cert = NID_PBE_CBC;
    this->SetNidMac(nid_key, iter, mac_iter);
    if (!pkey && !cert && !ca) {
        PKCS12err(PKCS12_F_PKCS12_CREATE, PKCS12_R_INVALID_NULL_ARGUMENT);
        return NULL;
    }
    if (pkey && cert) {
        if (!X509_check_private_key(cert, pkey))
            return NULL;
        X509_digest(cert, EVP_sha384(), keyid, &keyidlen);
    }
    if (SetCertPkcs12(cert, bag, bags, keyid, keyidlen, ca, name, &safes, nid_cert, iter, pass) == RET_FAILED)
        goto err;

    if (SetPkeyPkcs12(pkey, bag, bags, name, &safes, iter, keyPass, keytype, nid_key, keyid, keyidlen) == RET_FAILED)
        goto err;

    p12 = PKCS12_add_safes(safes, 0);
    if (!p12)
        goto err;
    sk_PKCS7_pop_free(safes, PKCS7_free);
    safes = NULL;
    if ((mac_iter != -1) &&
        !PKCS12_set_mac(p12, pass, -1, NULL, 0, mac_iter, NULL))
        goto err;
    return p12;

err:
    sk_PKCS7_pop_free(safes, PKCS7_free);
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
                                  unsigned char* keyid, unsigned int keyidlen, STACK_OF(X509)* ca,
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
    for (int i = 0; i < sk_X509_num(ca); i++) {
        if (!PKCS12_add_cert(&bags, sk_X509_value(ca, i))) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            bags = NULL;
            return RET_FAILED;
        }
    }
    if (bags && !PKCS12_add_safe(&(*safes), bags, nid_cert, iter, pass)) {
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
    if (bags && !PKCS12_add_safe(&(*safes), bags, -1, 0, NULL)) {
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
    if (!X509at_add1_attr(&(bag->attrib), attr))
        return RET_FAILED;
    return RET_OK;
}

int KeyStoreHelper::ParseBag(PKCS12_SAFEBAG* bag, const char* pass, int passlen,
                             EVP_PKEY** pkey, STACK_OF(X509)* ocerts)
{
    PKCS8_PRIV_KEY_INFO* p8;
    X509* x509;
    const ASN1_TYPE* attrib;
    ASN1_BMPSTRING* fname = NULL;
    ASN1_OCTET_STRING* lkid = NULL;
    if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_friendlyName)))fname = attrib->value.bmpstring;
    if ((attrib = PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID)))lkid = attrib->value.octet_string;
    switch (PKCS12_SAFEBAG_get_nid(bag)) {
        case NID_keyBag:
            if (!pkey || *pkey)return RET_OK;
            *pkey = EVP_PKCS82PKEY(PKCS12_SAFEBAG_get0_p8inf(bag));
            if (*pkey == NULL)return RET_FAILED;
            break;
        case NID_pkcs8ShroudedKeyBag:
            if (!pkey || *pkey)return RET_OK;
            if ((p8 = PKCS12_decrypt_skey(bag, pass, passlen)) == NULL)return RET_FAILED;
            *pkey = EVP_PKCS82PKEY(p8);
            PKCS8_PRIV_KEY_INFO_free(p8);
            if (!(*pkey))return RET_FAILED;
            break;
        case NID_certBag:
            if (PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate)return RET_OK;
            if ((x509 = PKCS12_SAFEBAG_get1_cert(bag)) == NULL)return RET_FAILED;
            if (lkid && !X509_keyid_set1(x509, lkid->data, lkid->length)) {
                X509_free(x509);
                return RET_FAILED;
            }
            if (fname) {
                int len;
                unsigned char* data;
                len = ASN1_STRING_to_UTF8(&data, fname);
                if (!X509AliasSet1(len, x509, data)) {
                    return RET_FAILED;
                }
            }
            if (!sk_X509_push(ocerts, x509)) {
                X509_free(x509);
                return RET_FAILED;
            }
            break;
        default:
            return RET_OK;
    }
    return RET_OK;
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
                              int passlen, EVP_PKEY** pkey, STACK_OF(X509)* ocerts)
{
    int i;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (this->ParseBag(sk_PKCS12_SAFEBAG_value(bags, i), pass, passlen, pkey, ocerts) == RET_FAILED)
            return RET_FAILED;
    }
    return RET_OK;
}