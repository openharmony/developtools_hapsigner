#include "sign_tool_service_impl.h"
#include "pkcs7_data.h"
#include "profile_sign_tool.h"
#include "nlohmann/json.hpp"
#include "provision_info.h"
#include "provision_verify.h"
#include "signature_tools_errno.h"
#include "Local_sign_provider.h"
#include "signature_tools_log.h"
#include "param_constants.h"
#include "hap_verify_v2.h"
#include "constant.h"
#include  <ctime>

using namespace OHOS::SignatureTools;
bool SignToolServiceImpl::GenerateCA(Options* options)
{
    bool flag = true;
    std::unique_ptr<LocalizationAdapter> adapter = std::make_unique<LocalizationAdapter>(options);
    std::unique_ptr<FileUtils> sutils = std::make_unique<FileUtils>();
    bool isEmpty = sutils->IsEmpty(options->GetString(Options::ISSUER_KEY_ALIAS));
    EVP_PKEY* subKey = adapter->GetAliasKey(true);
    if (!subKey) {
        SIGNATURE_TOOLS_LOGE("failed to get subKey!");
        return false;
    }
    EVP_PKEY* rootKey = nullptr;
    std::string ksFile = options->GetString(Options::KEY_STORE_FILE);
    if (ksFile.empty()) {
        SIGNATURE_TOOLS_LOGE("failed to get key store file!");
        return false;
    }
    std::string iksFile = options->GetString(Options::ISSUER_KEY_STORE_FILE);
    if (iksFile.empty()) {
        SIGNATURE_TOOLS_LOGE("failed to get issuer key store file!");
    }
    if (isEmpty) {
        HandleIssuerKeyAliasEmpty(iksFile, &sutils, options);
        rootKey = subKey;
    } else {
        HandleIsserKeyAliasNotEmpty(options);
        adapter->SetIssuerKeyStoreFile(true);
        rootKey = adapter->GetAliasKey(false);
    }
    X509* cert = nullptr;
    if (isEmpty) {
        flag = GenerateRootCertToFile(options, rootKey, cert);
    } else {
        flag = GenerateSubCertToFile(options, rootKey, cert);
    }
    return flag;
}
bool SignToolServiceImpl::GenerateRootCertToFile(Options* options, EVP_PKEY* rootKey, X509* cert)
{
    std::string signAlg = options->GetString(Options::SIGN_ALG);
    std::string subject = options->GetString(Options::SUBJECT);
    int caRes = 0;
    std::string outFile = "";
    if (signAlg.empty() || subject.empty()) {
        SIGNATURE_TOOLS_LOGE("failed to get signalg or subject!");
        return false;
    }
    X509_REQ* csr = CertTools::GenerateCsr(rootKey, signAlg, subject);
    if (!csr) {
        SIGNATURE_TOOLS_LOGE("failed to generate csr request!");
        goto err;
    }
    cert = CertTools::GenerateRootCertificate(rootKey, csr, options);
    if (!cert) {
        SIGNATURE_TOOLS_LOGE("failed to generate root cert!");
        goto err;
    }
    caRes = X509_verify(cert, rootKey);
    if (caRes != 1) {
        CMD_ERROR_MSG("VERIFY_ERROR", VERIFY_ERROR, "rootcert verify failed");
    }   
    outFile = options->GetString(Options::OUT_FILE);
    if (!outFile.empty()) {
        CertTools::SaveCertTofile(outFile, cert);
    } else {
        return PrintX509FromMemory(cert);
    }
    return true;
err:
    EVP_PKEY_free(rootKey);
    X509_REQ_free(csr);
    return false;

}

bool SignToolServiceImpl::GenerateSubCertToFile(Options* options, EVP_PKEY* rootKey, X509* cert)
{
    if (rootKey == nullptr) {
        SIGNATURE_TOOLS_LOGE("do not generate subcert directly,please generate rootcert first!");
        return false;
    }
    std::string signAlg = options->GetString(Options::SIGN_ALG);
    std::string issuer = options->GetString(Options::ISSUER);
    if (signAlg.empty() || issuer.empty()) {
        SIGNATURE_TOOLS_LOGE("failed to get signalg or issuer!");
        return false;
    }
    X509_REQ* csr = CertTools::GenerateCsr(rootKey, signAlg, issuer);
    if (!csr) {
        SIGNATURE_TOOLS_LOGE("failed to generate csr!");
        return false;
    } 
    cert = CertTools::GenerateSubCert(rootKey, csr, options);
    if (!cert) {
        SIGNATURE_TOOLS_LOGE("failed to generate sub ca cert!");
        EVP_PKEY_free(rootKey);
        X509_REQ_free(csr);
        return false;
    }
    int res = X509_verify(cert, rootKey);
    if (res != 1) {
        CMD_ERROR_MSG("VERIFY_ERROR", VERIFY_ERROR, "subcert verify failed");
        return false;
    }   
    std::string outFile = options->GetString(Options::OUT_FILE);
    if (!outFile.empty()) {
        CertTools::SaveCertTofile(outFile, cert);
    } else {
        PrintX509FromMemory(cert);
    }
    return true;
}

bool SignToolServiceImpl::HandleIssuerKeyAliasEmpty(std::string iksFile,
   std::unique_ptr<FileUtils>* sutils, Options* options)
{
    if (!(*sutils)->IsEmpty(iksFile) && !options->Equals(Options::KEY_STORE_FILE, Options::ISSUER_KEY_STORE_FILE)) {
        SIGNATURE_TOOLS_LOGE("ksFile and iksFile are inconsistent!");
        return false;
    }
    if (options->find(Options::ISSUER_KEY_STORE_RIGHTS) != options->end()) {
        bool isEqual = options->Equals(Options::KEY_STORE_RIGHTS, Options::ISSUER_KEY_STORE_RIGHTS);
        if (!isEqual) {
            SIGNATURE_TOOLS_LOGE("KEY_STORE_RIGHTS and ISSUER_KEY_STORE_RIGHTS are  inconsistent!");
            return false;
        }
    }
    return true;
}

bool SignToolServiceImpl::HandleIsserKeyAliasNotEmpty(Options* options)
{
    if (options->find(Options::ISSUER_KEY_STORE_RIGHTS) != options->end()) {
        std::string fileType = options->GetString(Options::ISSUER_KEY_STORE_FILE);
        if (fileType.empty()) {
            SIGNATURE_TOOLS_LOGE("failed to get issuer keystore file !");
            return false;
        }
        if (FileUtils::ValidFileType(fileType, { "p12", "jks" })) {
            SIGNATURE_TOOLS_LOGE("issuer keystore file type is inconsistent!");
            return false;
        }
    }
    return true;
}

bool SignToolServiceImpl::GenerateCert(Options* options)
{
    std::unique_ptr<LocalizationAdapter> adapter = std::make_unique<LocalizationAdapter>(options);
    EVP_PKEY* subjectkeyPair = adapter->GetAliasKey(false);
    if (!subjectkeyPair) {
        SIGNATURE_TOOLS_LOGE("failed to get subject key pair!");
        return false;
    }
    if (options->find(Options::ISSUER_KEY_STORE_RIGHTS) != options->end()) {
        adapter->SetIssuerKeyStoreFile(true);
    }
    EVP_PKEY* rootKeyPair = adapter->GetIssureKeyByAlias();
    if (!rootKeyPair) {
        SIGNATURE_TOOLS_LOGE("failed to get root key pair!");
        return false;
    }
    adapter->ResetPwd();
    std::string signAlg = options->GetString(Options::SIGN_ALG);
    std::string subject = options->GetString(Options::SUBJECT);
    if (signAlg.empty() || subject.empty()) {
        SIGNATURE_TOOLS_LOGE("failed to get signalg or subject!");
        return false;
    }
    X509_REQ* csr = CertTools::GenerateCsr(subjectkeyPair, signAlg, subject);
    if (!csr) {
        SIGNATURE_TOOLS_LOGE("failed to generate csr request!");
        return false;
    }
    X509* cert = CertTools::GenerateCert(rootKeyPair, csr, options);
    if (!cert) {
        SIGNATURE_TOOLS_LOGE("failed to general cert!");
        EVP_PKEY_free(rootKeyPair);
        X509_REQ_free(csr);
        return false;
    }
    int myCertRes = X509_verify(cert, rootKeyPair);
    if (myCertRes != 1) {
        CMD_ERROR_MSG("VERIFY_ERROR", VERIFY_ERROR, "generalcert verify failed");
        return false;
    }  
    std::string outFile = options->GetString(Options::OUT_FILE);
    if (!outFile.empty()) {
        CertTools::SaveCertTofile(outFile, cert);
    } else {
        return PrintX509FromMemory(cert);
    }
    return true;
}
bool SignToolServiceImpl::GenerateKeyStore(Options* options)
{
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(options);
    std::string keyAlias = adaptePtr->options->GetString(Options::KEY_ALIAS);
    if (keyAlias.empty()) {
        SIGNATURE_TOOLS_LOGE("The key alias cannot be empty!");
        return false;
    }

    EVP_PKEY* keyPair = nullptr;
    int status = adaptePtr->IsExist(keyAlias);
    if (status != RET_FAILED) {
        adaptePtr->ResetPwd();
        if (status == RET_OK)
            CMD_ERROR_MSG("KEY_ERROR", KEY_ERROR,"The key alias already exists and cannot be generated repeatedly");
        return false;
    }

    keyPair = adaptePtr->GetAliasKey(true);
    adaptePtr->ResetPwd();
    if (keyPair == nullptr) {
        SIGNATURE_TOOLS_LOGE("failed to get keypair!");
        return false;
    }
    EVP_PKEY_free(keyPair);
    return true;
}
bool SignToolServiceImpl::GenerateCsr(Options* options)
{
    std::unique_ptr<LocalizationAdapter> adapter = std::make_unique<LocalizationAdapter>(options);
    EVP_PKEY* keyPair = adapter->GetAliasKey(false);
    if (!keyPair) {
        SIGNATURE_TOOLS_LOGE("failed to get keypair!");
        CMD_ERROR_MSG("KEY_ERROR", KEY_ERROR, "Failed to get keypair! "
            "Check if the keypair existed in the keystore.");
        adapter->ResetPwd();
        return false;
    }
    adapter->ResetPwd();
    X509_REQ* csr = nullptr;
    std::string signAlg = options->GetString(Options::SIGN_ALG);
    std::string subject = options->GetString(Options::SUBJECT);
    if (signAlg.empty() || subject.empty()) {
        SIGNATURE_TOOLS_LOGE("failed to get signalg or subject!");
        CMD_ERROR_MSG("PARAM_NOT_EXIST_ERROR", PARAM_NOT_EXIST_ERROR,
            "Please check if signalg or subject has been specified which is required.");
        return false;
    }
    csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    if (!csr) {
        SIGNATURE_TOOLS_LOGE("failed to generate csr request!");
        EVP_PKEY_free(keyPair);
        return false;
    }
    std::string csrStr = CertTools::CsrToString(csr);
    EVP_PKEY_free(keyPair);
    if (csrStr.size() == 0) {
        SIGNATURE_TOOLS_LOGE("failed to transform cst to string!");
        return false;
    }
    std::string outFile = options->GetString(Options::OUT_FILE);
    return OutputString(csrStr, outFile);
}
bool SignToolServiceImpl::OutputString(std::string content, std::string file)
{
    if (file.size() == 0) {
        if (content.size() != 0) {
            puts(content.c_str());
            return true;
        } else {
            SIGNATURE_TOOLS_LOGE("failed to output csr content!");
            return false;
        }
    }
    std::ofstream outFile(file.c_str());
    if (!outFile.is_open()) {
        SIGNATURE_TOOLS_LOGE("failed to open the outFile!");
        return false;
    }
    outFile << content;
    outFile.close();
    return true;
}
bool SignToolServiceImpl::X509CertVerify(X509* cert, EVP_PKEY* privateKey)
{
    if (!cert) {
        EVP_PKEY_free(privateKey);
        SIGNATURE_TOOLS_LOGE("Failed to generate profile cert!");
        return false;
    }
    if (!X509_verify(cert, privateKey)) {
        EVP_PKEY_free(privateKey);
        X509_free(cert);
        SIGNATURE_TOOLS_LOGE("private key verify profile cert failed!");
        return false;
    }
    return true;
}

X509_REQ* SignToolServiceImpl::GetCsr(EVP_PKEY* keyPair, std::string signAlg, std::string subject)
{
    if (signAlg.empty() || subject.empty()) {
        EVP_PKEY_free(keyPair);
        SIGNATURE_TOOLS_LOGE("failed to get signalg or subject!");
        return nullptr;
    }
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    if (!csr) {
        EVP_PKEY_free(keyPair);
        SIGNATURE_TOOLS_LOGE("failed to generate csr!");
        return nullptr;
    }
    return csr;
}
bool SignToolServiceImpl::GenerateAppCert(Options* options)
{
    std::unique_ptr<LocalizationAdapter> adapter = std::make_unique<LocalizationAdapter>(options);
    EVP_PKEY* keyPair = adapter->GetAliasKey(false);
    if (!keyPair) {
        SIGNATURE_TOOLS_LOGE("failed to get keypair!");
        return false;
    }
    adapter->SetIssuerKeyStoreFile(true);
    EVP_PKEY* issueKeyPair = adapter->GetIssureKeyByAlias();
    if (!issueKeyPair) {
        EVP_PKEY_free(keyPair);
        SIGNATURE_TOOLS_LOGE("failed to get issuer keypair!");
        return false;
    }
    adapter->ResetPwd();
    X509_REQ* csr = nullptr;
    std::string signAlg = adapter->options->GetString(Options::SIGN_ALG);
    std::string subject = adapter->options->GetString(Options::SUBJECT);
    if (!(csr = GetCsr(keyPair, signAlg, subject))) {
        EVP_PKEY_free(issueKeyPair);
        return false;
    }
    X509_NAME* issuerName = X509_NAME_new();
    X509* x509Certificate = CertTools::GenerateEndCert(csr, issueKeyPair, *adapter,
                                                       PROFILE_SIGNING_CAPABILITY,
                                                       sizeof(PROFILE_SIGNING_CAPABILITY), issuerName);
    X509_NAME_free(issuerName);
    if (!X509CertVerify(x509Certificate, issueKeyPair)) {
        EVP_PKEY_free(keyPair);
        X509_REQ_free(csr);
        return false;
    }
    EVP_PKEY_free(keyPair);
    EVP_PKEY_free(issueKeyPair);
    X509_REQ_free(csr);
    return GetAndOutPutCert(*adapter, x509Certificate);
}
bool SignToolServiceImpl::GenerateProfileCert(Options* options)
{
    std::unique_ptr<LocalizationAdapter> adapter = std::make_unique<LocalizationAdapter>(options);
    EVP_PKEY* keyPair = adapter->GetAliasKey(false);
    if (!keyPair) {
        SIGNATURE_TOOLS_LOGE("failed to get keypair!");
        return false;
    }
    adapter->SetIssuerKeyStoreFile(true);
    EVP_PKEY* issueKeyPair = adapter->GetIssureKeyByAlias();
    if (!issueKeyPair) {
        EVP_PKEY_free(keyPair);
        SIGNATURE_TOOLS_LOGE("failed to get issuer keypair!");
        return false;
    }
    adapter->ResetPwd();
    X509_REQ* csr = nullptr;
    std::string signAlg = adapter->options->GetString(Options::SIGN_ALG);
    std::string subject = adapter->options->GetString(Options::SUBJECT);
    if (!(csr = GetCsr(keyPair, signAlg, subject))) {
        EVP_PKEY_free(issueKeyPair);
        return false;
    }
    X509_NAME* issuerName = X509_NAME_new();
    X509* x509Certificate = CertTools::GenerateEndCert(csr, issueKeyPair, *adapter,
                                                       PROFILE_SIGNING_CAPABILITY,
                                                       sizeof(PROFILE_SIGNING_CAPABILITY), issuerName);
    X509_NAME_free(issuerName);
    if (!X509CertVerify(x509Certificate, issueKeyPair)) {
        EVP_PKEY_free(keyPair);
        X509_REQ_free(csr);
        return false;
    }
    EVP_PKEY_free(keyPair);
    EVP_PKEY_free(issueKeyPair);
    X509_REQ_free(csr);
    return GetAndOutPutCert(*adapter, x509Certificate);
}
bool SignToolServiceImpl::GetAndOutPutCert(LocalizationAdapter& adapter, X509* cert)
{
    std::string outFile = adapter.options->GetString(Options::OUT_FILE);
    bool successflag = false;
    if (adapter.IsOutFormChain()) {
        std::vector<X509*> certificates;
        certificates.emplace_back(cert);
        certificates.emplace_back(adapter.GetSubCaCertFile());
        certificates.emplace_back(adapter.GetCaCertFile());
        if (certificates.size() < 1) {
            SIGNATURE_TOOLS_LOGE("failed to get cert!");
            return false;
        }
        if (outFile.empty()) {
            for (auto& cert : certificates) {
                if (PrintX509FromMemory(cert)) {
                    successflag = true;
                } else {
                    SIGNATURE_TOOLS_LOGE("Print certChain info error!");
                    successflag = false;
                    break;
                }
            }
            for (auto& cert : certificates) {
                X509_free(cert);
            }
            return successflag;
        }
        return OutPutCertChain(certificates, adapter.GetOutFile());
    }
    if (outFile.empty()) {
        if (PrintX509FromMemory(cert)) {
            successflag = true;
            X509_free(cert);
            return successflag;
        } else {
            SIGNATURE_TOOLS_LOGE("Print cert info error!");
            X509_free(cert);
            return successflag;
        }
    }
    return OutPutCert(cert, adapter.GetOutFile());
}
bool SignToolServiceImpl::SignProfile(Options* options)
{
    LocalizationAdapter adapter(options);
    const std::string inFile = adapter.GetInFile();
    const std::string outFile = adapter.GetOutFile();
    std::string provisionContent;
    std::string p7b;
    if (SignToolServiceImpl::GetProvisionContent(inFile, provisionContent) < 0) {
        SIGNATURE_TOOLS_LOGE("getProvisionContent failed\n");
        return false;
    }
    if (ProfileSignTool::GenerateP7b(adapter, provisionContent, p7b) < 0) {
        SIGNATURE_TOOLS_LOGE("generate P7b data failed\n");
        return false;
    }
    if (FileUtils::Write(p7b, outFile) < 0) {
        SIGNATURE_TOOLS_LOGE("write p7b data failed\n");
        return false;
    }
    return true;
}
bool SignToolServiceImpl::SignHap(Options* options)
{
    std::string mode = options->GetString(Options::MODE);
    std::shared_ptr<SignProvider> signProvider;
    if ("localSign" == mode) {
        signProvider = std::make_shared<LocalJKSSignProvider>();
    } else if ("remoteSign" == mode) {
        SIGNATURE_TOOLS_LOGE("not support remoteSign");
        return false;
        //signProvider = std::make_unique<RemoteSignProvider>();
    } else {
        SIGNATURE_TOOLS_LOGE("Resign mode. But not implemented yet");
        return false;
    }
    std::string inForm = options->GetString(Options::INFORM);

    if ("zip" == inForm) {
        return signProvider->Sign(options);
    } else if ("elf" == inForm) {
        SIGNATURE_TOOLS_LOGE("sign form [%s] is not suport yet", inForm.c_str());
    } else {
        SIGNATURE_TOOLS_LOGE("sign form [%s] is not suport yet", inForm.c_str());
        return false;
    }
    return true;
}
bool SignToolServiceImpl::VerifyProfile(Options* options)
{
    LocalizationAdapter adapter(options);
    std::string p7b;
    if (FileUtils::ReadFile(adapter.GetInFile(), p7b) < 0) {
        SIGNATURE_TOOLS_LOGE("read p7b data error\n");
        return false;
    }
    PKCS7Data p7Data;
    if (p7Data.Parse(p7b) < 0) {
        SIGNATURE_TOOLS_LOGE("verify profile failed\n");
        return false;
    }
    if (p7Data.Verify() < 0) {
        SIGNATURE_TOOLS_LOGE("verify profile failed\n");
        return false;
    }
    const std::string outFile = adapter.GetOutFile();
    std::string originalData;
    if (p7Data.GetContent(originalData) < 0) {
        SIGNATURE_TOOLS_LOGE("get content failed\n");
        return false;
    }
    if (outFile.empty()) {
        printf("%s\n", originalData.c_str());
    } else {
        std::ofstream out(outFile, std::ios::binary);
        out.write(originalData.data(), originalData.size());
    }
    return true;
}
bool SignToolServiceImpl::OutPutCertChain(std::vector<X509*>& certs, const std::string& outPutPath)
{
    SIGNATURE_TOOLS_LOGD("outPutPath = %{public}s", outPutPath.c_str());
    BIO* bio = nullptr;
    if (!(bio = BIO_new_file(outPutPath.c_str(), "wb"))) {
        SIGNATURE_TOOLS_LOGE("failed to open file");
        goto err;
    }
    for (auto cert : certs) {
        if (PEM_write_bio_X509(bio, cert) < 0) {
            SIGNATURE_TOOLS_LOGE("failed to write certChain to file!");
            goto err;  
        }
    }
    BIO_free(bio);
    for (auto cert : certs) {
        X509_free(cert);
    }
    return true;
err:
    HapVerifyOpensslUtils::GetOpensslErrorMessage();   
    BIO_free(bio);
    for (auto& cert : certs) {
        X509_free(cert);
    }
    return false;
}
bool SignToolServiceImpl::OutPutCert(X509* certs, const std::string& outPutPath)
{
    SIGNATURE_TOOLS_LOGE("outPutPath = %{public}s", outPutPath.c_str());
    BIO* bio = BIO_new_file(outPutPath.c_str(), "wb");
    if (!bio) {
        SIGNATURE_TOOLS_LOGE("failed to open file");
        goto err;
    }
    if (!PEM_write_bio_X509(bio, certs)) {
        SIGNATURE_TOOLS_LOGE("failed to write cert to file!");
        goto err;     
    }
    X509_free(certs);
    BIO_free(bio);
    return true;
err:
    HapVerifyOpensslUtils::GetOpensslErrorMessage();
    X509_free(certs);
    BIO_free(bio);
    return false;

}
int SignToolServiceImpl::GetProvisionContent(const std::string& input, std::string& ret)
{
    std::string bytes;
    if (FileUtils::ReadFile(input, bytes) < 0) {
        SIGNATURE_TOOLS_LOGE("provision read faild!\n");
        return READ_FILE_ERROR;
    }
    nlohmann::json obj = nlohmann::json::parse(bytes);
    if (obj.is_discarded() || (!obj.is_structured())) {
        SIGNATURE_TOOLS_LOGE("Parsing appProvision failed!");
        return PARSE_ERROR;
    }
    ret = obj.dump();
    ProvisionInfo provision;
    AppProvisionVerifyResult result = ParseProvision(ret, provision);
    if (result != PROVISION_OK) {
        SIGNATURE_TOOLS_LOGE("invalid provision\n");
        return INVALIDPARAM_ERROR;
    }
    return 0;
}
bool SignToolServiceImpl::PrintX509FromMemory(X509* cert)
{
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        BIO_free(bio);
        return false;
    }
    if (PEM_write_bio_X509(bio, cert) == 1) {
        BUF_MEM* bptr;
        BIO_get_mem_ptr(bio, &bptr);
        printf("%.*s", (int)bptr->length, bptr->data);
    } else {
        HapVerifyOpensslUtils::GetOpensslErrorMessage();
        printf("Error printing certificate.\n");
        return false;
    }
    BIO_free(bio);
    return true;
}
bool SignToolServiceImpl::VerifyHap(Options* option)
{
    std::string inForm = option->GetString(ParamConstants::PARAM_IN_FORM);
    if (inForm == "zip") {
        HapVerifyResult hapVerifyResult;
        HapVerifyV2 hapVerifyV2;
        int32_t ret = hapVerifyV2.Verify(option->GetString(Options::IN_FILE), hapVerifyResult, option);
        if (ret == VERIFY_SUCCESS) {
            printf("hap verify successed! \n");
            return true;
        }
        printf("hap verify failed ! \n");
        return false;
    } else {
        printf("This requirement was not implemented ! \n");
        return false;
    }
}