#include "hash.h"
#include "signature_tools_log.h"
#include "securec.h"

#define NUM_EXPAND 2
namespace OHOS {
    namespace SignatureTools {
        void Hash::addData(string data)
        {
            addData(data.data(), data.size());
        }
        void Hash::addData(const char* data, int length)
        {
            int ret = EVP_DigestUpdate(m_ctx, data, length);
            SIGNATURE_TOOLS_LOGI("addData EVP_DigestInit_ex ret = %{public}d", ret);
        }
        string Hash::result(Hash::Type type)
        {
            unsigned  int len = 0;
            unsigned  char md[HashLength.at(m_type)];
            int ret = EVP_DigestFinal_ex(m_ctx, md, &len);
            SIGNATURE_TOOLS_LOGI("result EVP_DigestInit_ex ret = %{public}d", ret);
            if (type == Type::Hex) {
                char res[len * NUM_EXPAND];
                for (int i = 0; i < len; i++) {
                    sprintf_s(&res[i * NUM_EXPAND], (len - i) * NUM_EXPAND, "%02x", md[i]);
                }
                return string(res, len * NUM_EXPAND);
            }
            return string(reinterpret_cast<char*>(md), len);
        }
        Hash::Hash(HashType type)
        {
            m_type = type;
            m_ctx = EVP_MD_CTX_new();
            if (m_ctx != nullptr) {
                int ret = EVP_DigestInit_ex(m_ctx, HashMethods.at(type)(), nullptr);
                SIGNATURE_TOOLS_LOGI("EVP_DigestInit_ex ret = %{public}d", ret);
            }
        }
        Hash::~Hash()
        {
            if (m_ctx != nullptr) {
                EVP_MD_CTX_free(m_ctx);
            }
        }
    }
}