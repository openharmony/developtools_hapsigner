#include "Local_sign_provider.h"
namespace OHOS {
    namespace SignatureTools {
        std::optional<X509_CRL*> LocalJKSSignProvider::GetCrl()
        {
            return std::optional<X509_CRL*>();
        }
        bool LocalJKSSignProvider::CheckParams(Options* options)
        {
            if (!SignProvider::CheckParams(options)) {
                printf("Parameter check failed !\n");
                return false;
            }
            std::vector<std::string> paramFileds;
            paramFileds.emplace_back(ParamConstants::PARAM_LOCAL_JKS_KEYSTORE);
            paramFileds.emplace_back(ParamConstants::PARAM_LOCAL_JKS_KEYSTORE_CODE);
            paramFileds.emplace_back(ParamConstants::PARAM_LOCAL_JKS_KEYALIAS_CODE);
            std::unordered_set<std::string> paramSet = ParamProcessUtil::initParamField(paramFileds);
            for (auto it = options->begin(); it != options->end(); it++) {
                if (paramSet.find(it->first) != paramSet.end()) {
                    size_t size = it->first.size();
                    std::string str = it->first.substr(size - 3);
                    if (str == "Pwd") {
                        std::string strPwd = options->GetChars(it->first);
                        signParams.insert(std::make_pair(it->first, strPwd));
                    } else {
                        signParams.insert(std::make_pair(it->first, options->GetString(it->first)));
                    }
                }
            }
            if (!CheckSignCode()) {
                printf("Error: PARAM_SIGN_CODE Parameter check error !");
                return false;
            }
            return true;
        }
        bool LocalJKSSignProvider::CheckPublicKeyPath()
        {
            std::string publicCertsFile = signParams[ParamConstants::PARAM_LOCAL_PUBLIC_CERT];
            if (!FileUtils::IsValidFile(publicCertsFile)) {
                return false;
            }
            std::ifstream publicKeyFile(publicCertsFile);
            if (!publicKeyFile.is_open()) {
                printf("File opening failure !\n");
                publicKeyFile.close();
                return false;
            }
            publicKeyFile.close();
            return true;
        }
    }
}