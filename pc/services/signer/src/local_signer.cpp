#include "local_signer.h"
#include "signature_tools_log.h"
#include "pkcs7_data.h"
#include "assert.h"
namespace OHOS {
    namespace SignatureTools {
        /**
        * Create local signer.
        *
        * @param keyPair   Private key to sign
        * @param certificates Cert chain to sign
        */
        LocalSigner::LocalSigner(EVP_PKEY* keyPair, STACK_OF(X509)* certificates) :keyPair(keyPair),
        certificates(certificates)
        {
            assert(this->keyPair != NULL || this->certificates != NULL);
            PKCS7Data::SortX509Stack(this->certificates);
            assert(sk_X509_num(this->certificates)>0
                   &&X509_check_private_key(sk_X509_value(this->certificates, 0), this->keyPair) == 1);
        }
        LocalSigner::~LocalSigner()
        {
            if (this->keyPair) {
                EVP_PKEY_free(this->keyPair);
                this->keyPair = NULL;
            }
            if (this->certificates) {
                sk_X509_pop_free(certificates, X509_free);
                this->certificates = NULL;
            }
        }
        STACK_OF(X509_CRL)* LocalSigner::GetCrls()const
        {
            return NULL;
        }
        STACK_OF(X509)* LocalSigner::GetCertificates()const
        {
            return this->certificates;
        }
        std::string LocalSigner::GetSignature(const std::string& data, const std::string& signAlg)const
		{
            EVP_MD_CTX* md_ctx = NULL;
            EVP_PKEY_CTX* pkey_ctx = NULL;
            unsigned char* sigret = NULL;
            const EVP_MD* md = NULL;
            size_t siglen;
            std::string ret;
            if (signAlg == "SHA256withECDSA") {
                md = EVP_sha256();
            }
            else if (signAlg == "SHA384withECDSA") {
                md = EVP_sha384();
            }
            else {
                SIGNATURE_TOOLS_LOGE("unsupport sigAlg\n");
                return ret;
            }
            md_ctx = EVP_MD_CTX_new();
            if (EVP_DigestSignInit(md_ctx, &pkey_ctx, md, NULL, this->keyPair) < 0)
            {
                SIGNATURE_TOOLS_LOGE("sign init error");
                goto err;
            }
            if (EVP_DigestSignUpdate(md_ctx, data.data(), data.size()) != 1)
            {
                SIGNATURE_TOOLS_LOGE("update error!");
                goto err;
            }
            if (EVP_DigestSignFinal(md_ctx, NULL, &siglen) <= 0)
                goto err;
            sigret = reinterpret_cast<unsigned char*>(OPENSSL_malloc(siglen));
            if (EVP_DigestSignFinal(md_ctx, sigret, &siglen) != 1) {
                SIGNATURE_TOOLS_LOGE("sign final error");
                goto err;
            }
            ret.assign(reinterpret_cast<const char*>(sigret), siglen);
        err:
            OPENSSL_free(sigret);
            EVP_MD_CTX_free(md_ctx);
            return ret;
        }
    }
}