/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <memory>
#include <fstream>
#include <gtest/gtest.h>
#include "merkle_tree_builder.h"

using namespace OHOS::SignatureTools;

class MerkleTreeBuilderTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: GenerateMerkleTree
 * @tc.desc: Test function of MerkleTreeBuilder::GenerateMerkleTree() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(MerkleTreeBuilderTest, GenerateMerkleTree, testing::ext::TestSize.Level1)
{
    const FsVerityHashAlgorithm SHA256((char)1, "SHA-256", 256 / 8);
    std::ifstream inputStream("./codeSigning/entry-default-signed-so.hap", std::ios::binary);

    MerkleTreeBuilder builder;
    MerkleTree* merkleTree = builder.GenerateMerkleTree(inputStream, 69632, SHA256);

    EXPECT_NE(merkleTree, nullptr);
}
