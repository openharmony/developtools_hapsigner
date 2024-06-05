/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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