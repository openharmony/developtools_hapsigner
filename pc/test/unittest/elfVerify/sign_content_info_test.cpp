/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "sign_content_info.h"

using namespace OHOS::SignatureTools;

class SignContentInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: GetByteContent001
 * @tc.desc: Test function of MerkleTreeBuilder::GenerateMerkleTree() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignContentInfoTest, GetByteContent001, testing::ext::TestSize.Level1)
{
    SignContentInfo signContentInfo;
    signContentInfo.SetVersion("111111112");
    std::vector<int8_t> content = signContentInfo.GetByteContent();
    int32_t size = content.size();

    EXPECT_EQ(size, 0);
}

/**
 * @tc.name: GetByteContent002
 * @tc.desc: Test function of MerkleTreeBuilder::GenerateMerkleTree() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignContentInfoTest, GetByteContent002, testing::ext::TestSize.Level1)
{
    SignContentInfo signContentInfo;
    signContentInfo.SetSize(0);
    signContentInfo.SetVersion("");
    std::vector<int8_t> content = signContentInfo.GetByteContent();
    int32_t size = content.size();

    EXPECT_EQ(size, 0);
}

/**
 * @tc.name: GetByteContent003
 * @tc.desc: Test function of MerkleTreeBuilder::GenerateMerkleTree() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignContentInfoTest, GetByteContent003, testing::ext::TestSize.Level1)
{
    SignContentInfo signContentInfo;
    signContentInfo.SetSize(3);
    signContentInfo.SetVersion("1");
    std::vector<int8_t> content = signContentInfo.GetByteContent();
    int32_t size = content.size();

    EXPECT_EQ(size, 0);
}