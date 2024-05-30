#include "param_process_util.h"
#include "signature_tools_log.h"
namespace OHOS {
    namespace SignatureTools {
        std::unordered_set<std::string> ParamProcessUtil::initParamField(const std::vector<std::string>& paramFields)
        {
            return std::unordered_set<std::string>(paramFields.begin(), paramFields.end());
        }
        bool ParamProcessUtil::getSignatureAlgorithm(const std::string& signatureAlgorithm,
                                                     SignatureAlgorithmClass& out)
        {
            if (signatureAlgorithm == ParamConstants::HAP_SIG_ALGORITHM_SHA256_ECDSA) {
                out = SignatureAlgorithmClass::ECDSA_WITH_SHA256_INSTANCE;
                return true;
            } else if (signatureAlgorithm == ParamConstants::HAP_SIG_ALGORITHM_SHA384_ECDSA) {
                out = SignatureAlgorithmClass::ECDSA_WITH_SHA384_INSTANCE;
                return true;
            } else {
                SIGNATURE_TOOLS_LOGE("get Signature Algorithm failed not support %s", signatureAlgorithm.c_str());
                return false;
            }
            return true;
        }
    }
}