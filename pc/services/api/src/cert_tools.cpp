#include "cert_tools.h"
#include <cassert>
#include "openssl/ec.h"
#include "openssl/obj_mac.h"
#include "openssl/asn1.h"
#include "signature_tools_log.h"
#include <string>
#include "constant.h"

#define BASIC_NUMBER_TWO  2
using namespace OHOS::SignatureTools;
static const char* oid = "1.3.6.1.4.1.2011.2.376.1.3";

void CertTools::SaveCertTofile(const std::string& filename, X509* cer)
{
    BIO* certBio = BIO_new_file(filename.data(), "w");
    if (!certBio) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("BIO_new failed\n");
        BIO_free(certBio);
        return;
    }

    if (PEM_write_bio_X509(certBio, cer) < 0) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("PEM_write_bio_X509 failed\n");
        BIO_free(certBio);
        return;
    }

    BIO_free(certBio);
}


X509* CertTools::SetBisicConstraintsPatchLen(Options* options, X509* cert)
{
    if (options->GetInt(Options::BASIC_CONSTRAINTS_PATH_LEN) == 0) {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:TRUE, pathlen:0");
        if (!ext) {          
            SIGNATURE_TOOLS_LOGE("create the expanding information failed\n");
            X509_EXTENSION_free(ext);
            goto err;
        }

        if (!X509_add_ext(cert, ext, -1)) {            
            SIGNATURE_TOOLS_LOGE("X509_add_ext failed\n");  
            X509_EXTENSION_free(ext);
            goto err;
            
        }
    } else {
        std::string setOptions =
            "CA:TRUE, pathlen:" + std::to_string(options->GetInt(Options::BASIC_CONSTRAINTS_PATH_LEN));
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);

        X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, setOptions.c_str());
        if (!ext) {
            SIGNATURE_TOOLS_LOGE("create the expanding information failed\n");          
            X509_EXTENSION_free(ext);
            goto err;
        }

        if (!X509_add_ext(cert, ext, -1)) {        
            SIGNATURE_TOOLS_LOGE("X509_add_ext failed\n");           
            X509_EXTENSION_free(ext);
            goto err;
        }
    }
    return cert;
err:
    HapVerifyOpensslUtils::GetOpensslErrorMessage();
    X509_free(cert);
    return nullptr;
}

X509* CertTools::SignForSubCert(X509* cert, X509_REQ* subcsr, X509_REQ* rootcsr, EVP_PKEY* ca_prikey, Options* options)
{
    std::string signAlg = "";
    if (!X509_set_pubkey(cert, X509_REQ_get_pubkey(subcsr))) {
        SIGNATURE_TOOLS_LOGE("X509_set_pubkey failed\n");
        goto err;
    }
    if (!X509_set_issuer_name(cert, X509_REQ_get_subject_name(rootcsr))) {        
        SIGNATURE_TOOLS_LOGE("X509_set_issuer_name failed\n");
        X509_NAME_free(X509_REQ_get_subject_name(rootcsr));
        goto err;
    }
    if (!X509_set_subject_name(cert, X509_REQ_get_subject_name(subcsr))) {      
        SIGNATURE_TOOLS_LOGE("X509_set_subject_name failed\n");      
        X509_NAME_free(X509_REQ_get_subject_name(subcsr));
        goto err;
    }
    signAlg = options->GetString(Options::SIGN_ALG);
    if (!SignCert(cert, ca_prikey, signAlg)) {
        return nullptr;
    }
    return cert;
err:
    HapVerifyOpensslUtils::GetOpensslErrorMessage();
    X509_free(cert);
    return nullptr;
}

X509* CertTools::SignCsrGenerateCert(X509_REQ* rootcsr, X509_REQ* subcsr,
    EVP_PKEY* keyPair, Options* options)
{
    X509* cert = X509_new();
    if (!SetCertVersion(cert, DEFAULT_CERT_VERSION) || !SetCertSerialNum(cert, DEFAULT_CERT_SERIALNUM)) {
        return nullptr;
    }
    int validity = options->GetInt(Options::VALIDITY);
    if (validity != 0) {
        if (!SetCertValidityStartAndEnd(cert, DEFAULT_START_VALIDITY, validity * DEFAULT_TIME)) {
            return nullptr;
        }
    }
    else {
        if (!SetCertValidityStartAndEnd(cert, DEFAULT_START_VALIDITY, DEFAULT_VALIDITY)) {
            return nullptr;
        }
    }
    if(!SetBisicConstraintsPatchLen(options, cert)) {
        return nullptr;
    }  
    if (!SignForSubCert(cert, subcsr, rootcsr, keyPair, options)) {
        return nullptr;
    }
    return  cert;
}

X509* CertTools::SetSubjectForCert(X509_REQ* certReq, X509* cert)
{
    X509_NAME* subject = X509_REQ_get_subject_name(certReq);
    if (subject == nullptr) {        
        SIGNATURE_TOOLS_LOGE("X509_REQ_get_subject_name failed\n");
        X509_REQ_free(certReq);
        goto err;
    }

    if (X509_set_subject_name(cert, subject) != 1) {       
        SIGNATURE_TOOLS_LOGE("X509_set_issuer_name failed\n");
        goto err;
    }
   
    if (X509_set_issuer_name(cert, subject) != 1) {        
        SIGNATURE_TOOLS_LOGE("X509_set_issuer_name failed\n");
        goto err;
     
    }
    return cert;
err:
    HapVerifyOpensslUtils::GetOpensslErrorMessage();
    X509_free(cert);
    X509_NAME_free(subject);
    return nullptr;
}

X509* CertTools::GenerateRootCertificate(EVP_PKEY* keyPair, X509_REQ* certReq, Options* options)
{
    X509* cert = X509_new();
    if (!SetCertVersion(cert, DEFAULT_CERT_VERSION) || !SetCertSerialNum(cert, DEFAULT_CERT_SERIALNUM)) {
        return nullptr;
    }
    int validity = options->GetInt(Options::VALIDITY);
    if (validity != 0) {
        if (!SetCertValidityStartAndEnd(cert, DEFAULT_START_VALIDITY, validity * DEFAULT_TIME)) {
            return nullptr;
        }
    }
    else {
        if (!SetCertValidityStartAndEnd(cert, DEFAULT_START_VALIDITY, DEFAULT_VALIDITY)) {
            return nullptr;
        }
    }
    if (!SetBisicConstraintsPatchLen(options, cert)) {
        return nullptr;
    }
    if (!SetSubjectForCert(certReq, cert)) {
        return nullptr;
    }  
    if (!SetCertPublickKey(cert, certReq)) {
        return nullptr;
    }
    std::string signAlg = options->GetString(Options::SIGN_ALG);
    if (!SignCert(cert, keyPair, signAlg)) {
        return nullptr;
    } 
    return cert;
}

X509* CertTools::GenerateSubCert(EVP_PKEY* keyPair, X509_REQ* rootcsr, Options* options)
{
    std::unique_ptr<LocalizationAdapter> adapter = std::make_unique< LocalizationAdapter>(options);    
    EVP_PKEY* subKey = adapter->GetAliasKey(false);
    if (subKey == nullptr) {
        SIGNATURE_TOOLS_LOGE("failed to get the keypair\n");
        return nullptr;
    }
    X509_REQ* subcsr = CertTools::GenerateCsr(subKey, options->GetString(Options::SIGN_ALG),
                                              options->GetString(Options::SUBJECT));
    if (!subcsr) {
        SIGNATURE_TOOLS_LOGE("failed to generate csr\n");
        return nullptr;
    }  
    X509* subCert = SignCsrGenerateCert(rootcsr, subcsr, keyPair, options);
    if (subCert == nullptr) {
        SIGNATURE_TOOLS_LOGE("failed to generate the subCert\n");
        return nullptr;
    }

    return subCert;
}

X509* CertTools::SetExpandedInfExtOne(X509* cert, Options* options,
                                      std::string critical, X509_EXTENSION* ext)
{
    if (options->find(Options::KEY_USAGE_CRITICAL) != options->end()) {
        bool keyUsageCritical = options->GetBool(Options::KEY_USAGE_CRITICAL);
        if (keyUsageCritical) {
            ext = X509V3_EXT_conf(NULL, NULL, "keyUsage",
                                  (critical + "," + options->GetString(Options::KEY_USAGE)).c_str());
        } else {
            ext = X509V3_EXT_conf(NULL, NULL, "keyUsage", (options->GetString(Options::KEY_USAGE)).c_str());
        }
    } else {
        ext = X509V3_EXT_conf(NULL, NULL, "keyUsage",
                              (critical + "," + options->GetString(Options::KEY_USAGE)).c_str());
    }
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return cert;
}

X509* CertTools::SetExpandedInfExtTwo(X509* cert, Options* options,
                                      std::string critical, X509_EXTENSION* ext)
{
    if (options->find(Options::EXT_KEY_USAGE_CRITICAL) != options->end()) {
        bool extKeyUsageCritical = options->GetBool(Options::EXT_KEY_USAGE_CRITICAL);
        if (!options->GetString(Options::EXT_KEY_USAGE).empty()) {
            if (extKeyUsageCritical) {
                ext = X509V3_EXT_conf(NULL, NULL, "extKeyUsage",
                                      (critical + "," + options->GetString(Options::EXT_KEY_USAGE)).c_str());
            } else {
                ext = X509V3_EXT_conf(NULL, NULL, "extKeyUsage", (options->GetString(Options::EXT_KEY_USAGE)).c_str());
            }
        }
    } else {
        ext = X509V3_EXT_conf(NULL, NULL, "extKeyUsage", (options->GetString(Options::EXT_KEY_USAGE)).c_str());
    }
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return cert;
}

X509* CertTools::SetExpandedInfExtThree(X509* cert, Options* options,
                                        std::string critical, X509_EXTENSION* ext)
{
    bool basicConstraints = options->GetBool(Options::BASIC_CONSTRAINTS);
    bool basicConstraintsCritical = options->GetBool(Options::BASIC_CONSTRAINTS_CRITICAL);
    bool basicConstraintsCa = options->GetBool(Options::BASIC_CONSTRAINTS_CA);
    if (basicConstraints) {
        if (basicConstraintsCritical) {
            if (basicConstraintsCa) {
                ext = X509V3_EXT_conf(NULL, NULL, "basicConstraints", "critical,CA:TRUE");
            }
            else {
                ext = X509V3_EXT_conf(NULL, NULL, "basicConstraints", "critical,CA:FALSE");
            }
        }
        else {
            if (basicConstraintsCa) {
                ext = X509V3_EXT_conf(NULL, NULL, "basicConstraints", "CA:TRUE");
            }
            else {
                ext = X509V3_EXT_conf(NULL, NULL, "basicConstraints", "CA:FALSE");
            }

        }
    }
    else {
        if (basicConstraintsCritical) {
            if (basicConstraintsCa) {
                ext = X509V3_EXT_conf(NULL, NULL, "", "critical,CA:TRUE");
            }
            else {
                ext = X509V3_EXT_conf(NULL, NULL, "", "critical,CA:FALSE");
            }
        }
        else {
            if (basicConstraintsCa) {
                ext = X509V3_EXT_conf(NULL, NULL, "", "CA:TRUE");
            }
            else {
                ext = X509V3_EXT_conf(NULL, NULL, "", "CA:FALSE");
            }

        }

    }   
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return cert;
}

X509* CertTools::SetExpandedInformation(X509* cert, Options* options)
{
    X509_EXTENSION* ext1 = nullptr;
    X509_EXTENSION* ext2 = nullptr;
    X509_EXTENSION* ext3 = nullptr;
    std::string critical = "critical";
    X509* certone = SetExpandedInfExtOne(cert, options, critical, ext1);
    if (certone == nullptr) {
        return nullptr;
    }
    X509* certtwo = SetExpandedInfExtTwo(certone, options, critical, ext2);
    if (certtwo == nullptr) {
        return nullptr;
    }
    X509* certthree = SetExpandedInfExtThree(certone, options, critical, ext3);
    if (certthree == nullptr) {
        return nullptr;
    }

    return certthree;
}

X509* CertTools::SetPubkeyAndSignCert(X509* cert, X509_REQ* issuercsr,
                                      X509_REQ* certReq, EVP_PKEY* keyPair, Options* options)
{
    if (!X509_set_issuer_name(cert, X509_REQ_get_subject_name(issuercsr))) {
        SIGNATURE_TOOLS_LOGE("X509_set_issuer_name failed\n");        
        X509_NAME_free(X509_REQ_get_subject_name(issuercsr));
        goto err;
    }

    if (!X509_set_subject_name(cert, X509_REQ_get_subject_name(certReq))) {
        
        SIGNATURE_TOOLS_LOGE("X509_set_subject_name failed\n");      
        X509_NAME_free(X509_REQ_get_subject_name(certReq));
        goto err;
    }

    if ((options->GetString(Options::SIGN_ALG)) == "SHA256withECDSA") {
        if (!X509_sign(cert, keyPair, EVP_sha256())) {          
            SIGNATURE_TOOLS_LOGE("X509_sign failed\n");
            goto err;
        }
    } else {
        if (!X509_sign(cert, keyPair, EVP_sha384())) {           
            SIGNATURE_TOOLS_LOGE("X509_sign failed\n");
            goto err;
        }
    }
    return cert;
err:
    HapVerifyOpensslUtils::GetOpensslErrorMessage();
    X509_free(cert);
    return nullptr;
}

X509* CertTools::GenerateCert(EVP_PKEY* keyPair, X509_REQ* certReq, Options* options)
{
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, options->GetString(Options::SIGN_ALG),
                                                 options->GetString(Options::ISSUER));
    if (issuercsr == nullptr) {
        SIGNATURE_TOOLS_LOGE("failed to generate the issuercsr\n");
        return nullptr;
    }
   
    X509* cert = X509_new();
    if (!SetCertVersion(cert, DEFAULT_CERT_VERSION) || !SetCertSerialNum(cert, DEFAULT_CERT_SERIALNUM)) {
        return nullptr;
    }
    int validity = options->GetInt(Options::VALIDITY);
    if (validity != 0) {
        if (!SetCertValidityStartAndEnd(cert, DEFAULT_START_VALIDITY, validity * DEFAULT_TIME)) {
            return nullptr;
        }
    }
    else {
        if (!SetCertValidityStartAndEnd(cert, DEFAULT_START_VALIDITY, DEFAULT_VALIDITY)) {
            return nullptr;
        }
    }
    if (!SetBisicConstraintsPatchLen(options, cert)) {
        return nullptr;
    }
    if (!SetCertPublickKey(cert, certReq)) {
        return nullptr;
    }
    if (!SetExpandedInformation(cert, options)) {
        return nullptr;
    } 
    if (!SetPubkeyAndSignCert(cert, issuercsr, certReq, keyPair, options)) {
        return nullptr;
    }
    
    return cert;
}

X509_REQ* CertTools::GenerateCsr(EVP_PKEY* evpPkey, std::string signAlgorithm, std::string subject)
{
    X509_NAME* name = nullptr;
    X509_REQ* req = X509_REQ_new();
    if (!req) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("X509_REQ_new failed\n");
        return nullptr;
    }

    if (!X509_REQ_set_pubkey(req, evpPkey)) {      
        SIGNATURE_TOOLS_LOGE("X509_REQ_set_pubkey failed\n");
        goto err;
    }

    name = BuildDN(subject, req);
    if (!name) {
        SIGNATURE_TOOLS_LOGE("failed to add subject into cert\n");
        return nullptr;
    }

    if (signAlgorithm == "SHA256withECDSA") {
        if (!X509_REQ_sign(req, evpPkey, EVP_sha256())) {           
            SIGNATURE_TOOLS_LOGE("X509_REQ_sign failed\n");
            goto err;
        }
    } else if (signAlgorithm == "SHA384withECDSA") {
        if (!X509_REQ_sign(req, evpPkey, EVP_sha384())) {         
            SIGNATURE_TOOLS_LOGE("X509_REQ_sign failed\n");
            goto err;
        }
    } else {
        
        SIGNATURE_TOOLS_LOGE("Sign algorithm format error\n");
        CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
            "Sign algorithm format error! Please check again.");
        goto err;
    }
    return req;
err:
    HapVerifyOpensslUtils::GetOpensslErrorMessage();
    X509_REQ_free(req);
    return nullptr;
}

std::string CertTools::CsrToString(X509_REQ* csr)
{
    BIO* csrBio = BIO_new(BIO_s_mem());
    if (!csrBio) {
        return "";
    }

    if (!PEM_write_bio_X509_REQ(csrBio, csr)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("PEM_write_bio_X509_REQ error\n");
        BIO_free(csrBio);
        return "";
    }

    BUF_MEM* data = nullptr;
    BIO_get_mem_ptr(csrBio, &data);
    if (!data) {
        BIO_free(csrBio);
        return "";
    }

    if (!data->data) {
        BIO_free(csrBio);
        return "";
    }
    std::string csrStr(data->data, data->length);
    BIO_free(csrBio);
    return csrStr;
}

X509* CertTools::ReadfileToX509(const std::string& filename)
{
    BIO* certBio = BIO_new_file(filename.c_str(), "rb");
    if (!certBio) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("BIO_new_file failed\n");
        BIO_free(certBio);
        return nullptr;
    }

    X509* cert = X509_new();
    if (!PEM_read_bio_X509(certBio, &cert, NULL, NULL)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("PEM_read_bio_X509 failed\n");
        X509_free(cert);
        BIO_free(certBio);
        return nullptr;
    }
    BIO_free(certBio);

    return cert;
}

bool CertTools::SetCertVersion(X509* cert, int versionNum)
{
    if (!X509_set_version(cert, versionNum)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set x509 cert version failed\n");
        X509_free(cert);
        return false;
    }
    return true;
}

bool CertTools::SetCertSerialNum(X509* cert, long serialNum)
{
    ASN1_INTEGER* ans1Num = nullptr;
    if (!(ans1Num = X509_get_serialNumber(cert))) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("get x509 cert serial num failed\n");
        X509_free(cert);
        return false;
    }
    if (!ASN1_INTEGER_set(ans1Num, serialNum)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set x509 cert serial number failed\n");
        X509_free(cert);
        return false;
    }
    return true;
}

bool CertTools::SetCertIssuerName(X509* cert, X509_NAME* issuer)
{
    if (!X509_set_issuer_name(cert, issuer)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set x509 cert issuer name failed\n");
        X509_free(cert);
        return false;
    }
    return true;
}

bool CertTools::SetCertSubjectName(X509* cert, X509_REQ* subjectCsr)
{
    X509_NAME* subject = nullptr;
    if (!(subject = X509_REQ_get_subject_name(subjectCsr))) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("get X509 cert subject name failed\n");
        X509_free(cert);
        return false;
    }
    if (!X509_set_subject_name(cert, subject)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set X509 cert subject name failed\n");
        X509_free(cert);
        return false;
    }
    return true;
}

bool CertTools::SetCertValidityStartAndEnd(X509* cert, long vilidityStart, long vilidityEnd)
{
    if (!X509_gmtime_adj(X509_getm_notBefore(cert), vilidityStart)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set cert vilidity start time failed\n");
        X509_free(cert);
        return false;
    }
    if (!X509_gmtime_adj(X509_getm_notAfter(cert), vilidityEnd)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set cert vilidity end time failed\n");
        X509_free(cert);
        return false;
    }
    return true;
}

bool CertTools::SetCertPublickKey(X509* cert, X509_REQ* subjectCsr)
{
    EVP_PKEY* publicKey = X509_REQ_get_pubkey(subjectCsr);
    if (!publicKey) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("get the pubkey from csr failed\n");
        X509_free(cert);
        return false;
    }
    if (!X509_set_pubkey(cert, publicKey)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set public key to cert failed\n");
        X509_free(cert);
        return false;
    }
    return true;
}

bool CertTools::SetBasicExt(X509* cert)
{
    X509_EXTENSION* basicExtension = X509V3_EXT_conf(NULL, NULL, NID_BASIC_CONST.c_str(),
                                                     DEFAULT_BASIC_EXTENSION.c_str());
    if (!X509_add_ext(cert, basicExtension, -1)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set basicExtension information failed\n");
        X509_free(cert);
        X509_EXTENSION_free(basicExtension);
        return false;
    }
    X509_EXTENSION_free(basicExtension);
    return true;
}

bool CertTools::SetkeyUsageExt(X509* cert)
{
    X509_EXTENSION* keyUsageExtension = X509V3_EXT_conf(NULL, NULL, NID_KEYUSAGE_CONST.c_str(),
                                                        DEFAULT_KEYUSAGE_EXTENSION.c_str());
    if (!X509_add_ext(cert, keyUsageExtension, -1)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set keyUsageExtension information failed\n");
        X509_free(cert);
        X509_EXTENSION_free(keyUsageExtension);
        return false;
    }
    X509_EXTENSION_free(keyUsageExtension);
    return true;
}

bool CertTools::SetKeyUsageEndExt(X509* cert)
{
    X509_EXTENSION* keyUsageEndExtension = X509V3_EXT_conf(NULL, NULL, NID_EXT_KEYUSAGE_CONST.c_str(),
                                                           DEFAULT_EXTEND_KEYUSAGE.c_str());
    if (!X509_add_ext(cert, keyUsageEndExtension, -1)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set keyUsageEndExtension information failed\n");
        X509_free(cert);
        X509_EXTENSION_free(keyUsageEndExtension);
        return false;
    }
    X509_EXTENSION_free(keyUsageEndExtension);
    return true;
}

bool CertTools::SetKeyIdentifierExt(X509* cert)
{
    unsigned char digest[SHA256_DIGEST_LENGTH] = { 0 };
    unsigned int digestLen = 0;
    if (X509_pubkey_digest(cert, EVP_sha256(), digest, &digestLen) != 1) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("digest x509 cert public key failed\n");
        X509_free(cert);
        return false;
    }
    ASN1_OCTET_STRING* pubKeyDigestData = ASN1_OCTET_STRING_new();
    if (!ASN1_OCTET_STRING_set(pubKeyDigestData, digest, digestLen)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set ANS1 pubKeyDigestData failed\n");
        X509_free(cert);
        ASN1_OCTET_STRING_free(pubKeyDigestData);
        return false;
    }
    X509_EXTENSION* subKeyIdentifierExtension = nullptr;
    subKeyIdentifierExtension = X509_EXTENSION_create_by_OBJ(NULL, OBJ_nid2obj(NID_subject_key_identifier),
                                                             0, pubKeyDigestData);
    if (!X509_add_ext(cert, subKeyIdentifierExtension, -1)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set subKeyIdentifierExtension information failed\n");
        X509_free(cert);
        ASN1_OCTET_STRING_free(pubKeyDigestData);
        X509_EXTENSION_free(subKeyIdentifierExtension);
        return false;
    }
    ASN1_OCTET_STRING_free(pubKeyDigestData);
    X509_EXTENSION_free(subKeyIdentifierExtension);
    return true;
}

bool CertTools::SetSignCapacityExt(X509* cert, const char signCapacity[], int capacityLen)
{
    ASN1_OCTET_STRING* certSignCapacityData = ASN1_OCTET_STRING_new();
    if (!ASN1_OCTET_STRING_set(certSignCapacityData, (const unsigned char*)signCapacity, capacityLen)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("failed to set pubkey digst into ASN1 object\n");
        X509_free(cert);
        ASN1_OCTET_STRING_free(certSignCapacityData);
        return false;
    }
    X509_EXTENSION* certSignCapacityExt = X509_EXTENSION_create_by_OBJ(NULL, OBJ_txt2obj(oid, 1),
                                                                       0, certSignCapacityData);
    if (!X509_add_ext(cert, certSignCapacityExt, -1)) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        SIGNATURE_TOOLS_LOGE("set certSignCapacityExt information failed\n");
        X509_free(cert);
        X509_EXTENSION_free(certSignCapacityExt);
        ASN1_OCTET_STRING_free(certSignCapacityData);
        return false;
    }
    X509_EXTENSION_free(certSignCapacityExt);
    ASN1_OCTET_STRING_free(certSignCapacityData);
    return true;
}

bool CertTools::SignCert(X509* cert, EVP_PKEY* privateKey, std::string signAlg)
{
    if (signAlg == SIGN_ALG_SHA256) {
        if (!X509_sign(cert, privateKey, EVP_sha256())) {
            HapVerifyOpensslUtils::GetOpensslErrorMessage();
            SIGNATURE_TOOLS_LOGE("sign X509 cert failed\n");
            return false;
        }
    } else {
        if (!X509_sign(cert, privateKey, EVP_sha384())) {
            HapVerifyOpensslUtils::GetOpensslErrorMessage();
            SIGNATURE_TOOLS_LOGE("sign X509 cert failed\n");
            return false;
        }
    }
    return true;
}

X509* CertTools::GenerateEndCert(X509_REQ* csr, EVP_PKEY* issuerKeyPair,
                                 LocalizationAdapter& adapter,
                                 const char signCapacity[], int capacityLen,
                                 X509_NAME* issuerName)
{
    X509* cert = X509_new();
    if (!SetCertVersion(cert, DEFAULT_CERT_VERSION) || !SetCertSerialNum(cert, DEFAULT_CERT_SERIALNUM)) {
        return nullptr;
    }
    X509_REQ* issuerReq = X509_REQ_new();
    std::string issuerStr = adapter.options->GetString(adapter.options->ISSUER);
    if (!SetCertIssuerName(cert, BuildDN(issuerStr, issuerReq)) || !SetCertSubjectName(cert, csr)) {
        X509_REQ_free(issuerReq);
        return nullptr;
    }
    X509_REQ_free(issuerReq);
    int validity = adapter.options->GetInt(adapter.options->VALIDITY);
    if (validity != 0) {
        if (!SetCertValidityStartAndEnd(cert, DEFAULT_START_VALIDITY, validity * DEFAULT_TIME)) {
            return nullptr;
        }
    } else {
        if (!SetCertValidityStartAndEnd(cert, DEFAULT_START_VALIDITY, DEFAULT_VALIDITY)) {
            return nullptr;
        }
    }
    if (!SetCertPublickKey(cert, csr)) {
        return nullptr;
    }
    if (!SetBasicExt(cert) || !SetkeyUsageExt(cert) || !SetKeyUsageEndExt(cert)) {
        return nullptr;
    }
    if (!SetKeyIdentifierExt(cert) || !SetSignCapacityExt(cert, signCapacity, capacityLen)) {
        return nullptr;
    }
    std::string signAlg = adapter.options->GetString(adapter.options->SIGN_ALG);
    if (!SignCert(cert, issuerKeyPair, signAlg)) {
        return nullptr;
    }
    return cert;
}