#include "profile_sign_tool.h"
#include "signer_factory.h"
#include "local_signer.h"
#include "localization_adapter.h"
#include "file_utils.h"
#include "pkcs7_data.h"
#include "verify_openssl_utils.h"
#include "signature_tools_errno.h"
namespace OHOS {
    namespace SignatureTools {
        ProfileSignTool::ProfileSignTool()
        {
        }
        int ProfileSignTool::GenerateP7b(LocalizationAdapter& adapter, const std::string& content, std::string& ret)
        {
            std::unique_ptr<SignerFactory> signerFactory=std::make_unique<SignerFactory>();
            if (signerFactory == NULL) {
                SIGNATURE_TOOLS_LOGE("create signerFactor failed\n");
                return INVALIDPARAM_ERROR;
            }
            std::shared_ptr<ISigner> signer(signerFactory->GetSigner(adapter));
            if (signer == NULL) {
                SIGNATURE_TOOLS_LOGE("get signer failed\n");
                return INVALIDPARAM_ERROR;
            }
            const std::string sigAlg = adapter.GetSignAlg();
            //ret 为生成的p7b数据
            if (SignProfile(content, signer, sigAlg, ret) < 0) {
                SIGNATURE_TOOLS_LOGE("profile sign failed\n");
                return SIGN_ERROR;
            }
            PKCS7Data p7Data;
            if (p7Data.Parse(ret) < 0) {
                SIGNATURE_TOOLS_LOGE("verify profile failed\n");
                return INIT_ERROR;
            }
            if (p7Data.Verify() < 0) {
                SIGNATURE_TOOLS_LOGE("verify profile failed\n");
                return VERIFY_ERROR;
            }
            return 0;
        }
        /**
        * @param content content to sign
        * @param signer signer
        * @param sigAlg sign algorithm  only SHAwith256 or SHAwith384
        * @param ret signed data
        * @return 0:success <0:error
        */
        int ProfileSignTool::SignProfile(const std::string& content, std::shared_ptr<ISigner> signer,
                                         const std::string& sigAlg, std::string& ret)
        {
            PKCS7Data p7Data;
            if (p7Data.Sign(content, signer, sigAlg, ret) < 0) {
                SIGNATURE_TOOLS_LOGE("SignProfile faild!\n");
                return PKCS7_SIGN_ERROR;
            }
            return 0;
        }
    }
}