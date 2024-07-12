#include <cstring>
#include <dlfcn.h>
#include <memory>
#include "../include/signer.h"
#include "remote_sign_provider.h"
#include "signer_factory.h"

using namespace OHOS::SignatureTools;

int main()
{
    std::shared_ptr<RemoteSignProvider> signProvider = std::make_shared<RemoteSignProvider>();

    SignerFactory signerFactory;
    std::shared_ptr<Signer> remoteSigner = signerFactory.LoadRemoteSigner();

    std::string signedData = remoteSigner->GetSignature("abcd", "SHA256withECDSA");
    STACK_OF(X509_CRL)* crls = remoteSigner->GetCrls();
    STACK_OF(X509)* certs = remoteSigner->GetCertificates();

    return 0;
}