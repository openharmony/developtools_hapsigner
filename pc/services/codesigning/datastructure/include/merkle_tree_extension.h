/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef SIGNATURETOOLS_MERKLE_TREE_EXTENSION_H
#define SIGNATURETOOLS_MERKLE_TREE_EXTENSION_H
#include <vector>
#include <string>
#include "extension.h"
#include "signature_tools_log.h"
namespace OHOS {
    namespace SignatureTools {
        // 继承类的构造函数一般记得先构造基类,再初始化自己特有成员
        class MerkleTreeExtension : public Extension {
        public:
            MerkleTreeExtension();
            MerkleTreeExtension(int64_t merkleTreeSize, int64_t merkleTreeOffset, std::vector<int8_t> rootHash);
            virtual ~MerkleTreeExtension();
        public:
            virtual int32_t getSize();
            virtual std::vector<int8_t> toByteArray();
            virtual std::string toString();
            int64_t getMerkleTreeSize();
            int64_t getMerkleTreeOffset();
            void setMerkleTreeOffset(int64_t offset);
            static MerkleTreeExtension* fromByteArray(std::vector<int8_t> bytes);
        public:
            static const int32_t MERKLE_TREE_INLINED;
            static const int32_t MERKLE_TREE_EXTENSION_DATA_SIZE;
        private:
            static const int32_t ROOT_HASH_SIZE;
            static const int32_t PAGE_SIZE_4K;
            int64_t merkleTreeSize;
            int64_t merkleTreeOffset;
            std::vector<int8_t> rootHash;
        };
    }
}
#endif
