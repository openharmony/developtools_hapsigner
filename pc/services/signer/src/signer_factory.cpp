#include "signer_factory.h"
namespace OHOS {
    namespace SignatureTools {
        std::shared_ptr<ISigner> SignerFactory::GetSigner(LocalizationAdapter& adapter)const
        {
            EVP_PKEY* keyPair = adapter.GetAliasKey(false);
            if (keyPair == NULL) {
                SIGNATURE_TOOLS_LOGE("NULL keyPair");
                return NULL;
            } //adapter.ResetPwd();
            std::shared_ptr<ISigner> signer=std::make_shared<LocalSigner>(keyPair, adapter.GetSignCertChain());
            if (signer == NULL) {
                SIGNATURE_TOOLS_LOGE("create LocalSigner failed");
                EVP_PKEY_free(keyPair);
                return NULL;
            }
            return signer;
        }
    }
}