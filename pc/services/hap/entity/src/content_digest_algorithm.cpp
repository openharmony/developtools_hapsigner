#include "content_digest_algorithm.h"
namespace OHOS {
    namespace SignatureTools {
        const ContentDigestAlgorithm ContentDigestAlgorithm::SHA256("SHA-256", 256 / 8);
        const ContentDigestAlgorithm ContentDigestAlgorithm::SHA384("SHA-384", 384 / 8);
        const ContentDigestAlgorithm ContentDigestAlgorithm::SHA512("SHA-512", 512 / 8);
        // 默认构造函数
        ContentDigestAlgorithm::ContentDigestAlgorithm()
            : digestAlgorithm(""),  // 设置默认算法名称为空
            digestOutputByteSize(0)
        {
        }  // 设置默认输出字节大小为0
                  // 拷贝构造函数
        ContentDigestAlgorithm::ContentDigestAlgorithm(const ContentDigestAlgorithm& other)
            : digestAlgorithm(other.digestAlgorithm),
            digestOutputByteSize(other.digestOutputByteSize)
        {
        }
        // 赋值运算符
        ContentDigestAlgorithm& ContentDigestAlgorithm::operator=(const ContentDigestAlgorithm& other)
        {
            if (this != &other) {
                digestAlgorithm = other.digestAlgorithm;
                digestOutputByteSize = other.digestOutputByteSize;
            }
            return *this;
        }
        ContentDigestAlgorithm::ContentDigestAlgorithm(const std::string& digestAlgorithm,
            const int digestOutputByteSize)
            : digestAlgorithm(digestAlgorithm), digestOutputByteSize(digestOutputByteSize)
        {
        }
        std::string ContentDigestAlgorithm::GetDigestAlgorithm()
        {
            return digestAlgorithm;
        }
        int ContentDigestAlgorithm::GetDigestOutputByteSize()
        {
            return digestOutputByteSize;
        }
    }
}