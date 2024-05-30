#include "signature_algorithm.h"
namespace OHOS {
    namespace SignatureTools {
        SignatureAlgorithmClass::SignatureAlgorithmClass() :id(SignatureAlgorithmId::ECDSA_WITH_SHA256),
            keyAlgorithm(""), contentDigestAlgorithm(ContentDigestAlgorithm::SHA256),
            signatureAlgAndParams("", nullptr)
        {
        }
        SignatureAlgorithmClass::SignatureAlgorithmClass(const SignatureAlgorithmClass& other) : id(other.id),
            keyAlgorithm(other.keyAlgorithm), contentDigestAlgorithm(other.contentDigestAlgorithm),
            signatureAlgAndParams(other.signatureAlgAndParams.first, nullptr)
        {
        }
        SignatureAlgorithmClass& SignatureAlgorithmClass::operator=(const SignatureAlgorithmClass& other)
        {
            if (this != &other) {
                id = other.id;
                keyAlgorithm = other.keyAlgorithm;
                contentDigestAlgorithm = other.contentDigestAlgorithm;
                // 对于signatureAlgAndParams中的void*，确保正确处理（可能需要深拷贝或其他逻辑）
                signatureAlgAndParams.first = other.signatureAlgAndParams.first;
                // 注意：这里只是简单地复制了指针，具体是否需要深拷贝取决于它指向的内容。
                signatureAlgAndParams.second = other.signatureAlgAndParams.second;
            }
            return *this;
        }
        SignatureAlgorithmClass::~SignatureAlgorithmClass()
        {
        }
        // 静态查找方法，通过ID找到对应的SignatureAlgorithm实例
        const SignatureAlgorithmClass* SignatureAlgorithmClass::FindById(SignatureAlgorithmId id)
        {
            if (id == SignatureAlgorithmId::ECDSA_WITH_SHA256) return &ECDSA_WITH_SHA256_INSTANCE;
            if (id == SignatureAlgorithmId::ECDSA_WITH_SHA384) return &ECDSA_WITH_SHA384_INSTANCE;
            return nullptr;
        }
        SignatureAlgorithmClass::SignatureAlgorithmClass(SignatureAlgorithmId id_, std::string keyAlg_,
            ContentDigestAlgorithm digestAlg_, std::pair<std::string, void*> sigParams_)
            : id(id_), keyAlgorithm(keyAlg_), contentDigestAlgorithm(digestAlg_), signatureAlgAndParams(sigParams_)
        {
        }
        // 静态成员变量的初始化
        const SignatureAlgorithmClass SignatureAlgorithmClass::ECDSA_WITH_SHA256_INSTANCE{
            SignatureAlgorithmId::ECDSA_WITH_SHA256, "EC", ContentDigestAlgorithm::SHA256,
            {"SHA256withECDSA", nullptr} };
        const SignatureAlgorithmClass SignatureAlgorithmClass::ECDSA_WITH_SHA384_INSTANCE{
            SignatureAlgorithmId::ECDSA_WITH_SHA384, "EC", ContentDigestAlgorithm::SHA384,
            {"SHA384withECDSA", nullptr} };
    }
}