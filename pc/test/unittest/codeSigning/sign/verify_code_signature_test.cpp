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

#include <memory>
#include <fstream>
#include <gtest/gtest.h>
#include "verify_code_signature.h"

using namespace OHOS::SignatureTools;

/*
 * 测试套件,固定写法
 */
class VerifyCodeSignatureTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: AreVectorsEqual
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, AreVectorsEqual, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> vec1{ 21, 53, 29, 18, -17, 56, 92, 60, 29, 10, 28, 18, 19, 52, 59, 92 };
    std::vector<int8_t> vec2{ 21, 53, 29, 18, -17, 56, 92, 60, 29, 10, 28, 18, 19, 52, 59, 92 };
    bool flag = VerifyCodeSignature::AreVectorsEqual(vec1, vec2);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: VerifyCodeSign
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyCodeSign, testing::ext::TestSize.Level1)
{
    std::pair<std::string, std::string> pairResult = std::make_pair("", "debug");
    std::string file = "./codeSigning/entry-default-signed-so.hap";
    int64_t offset = 1397151;
    int64_t length = 23193;
    std::string fileFormat = "hap";
    std::string profileContent = "";
    VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);
    CodeSignBlock csb;
    bool flag = VerifyCodeSignature::VerifyCodeSign(file, pairResult, csb);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyHap001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyHap001, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/entry-default-signed-so.hap";
    int64_t offset = 1397151;
    int64_t length = 23193;
    std::string fileFormat = "hap";
    std::string profileContent = "";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: VerifyHap002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyHap002, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/entry-default-signed-so.hap";
    int64_t offset = 1397151;
    int64_t length = 23193;
    std::string fileFormat = "";
    std::string profileContent = "";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: VerifyHap003
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyHap003, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/entry-default-signed-so.hap";
    int64_t offset = 1397151;
    int64_t length = 23194;
    std::string fileFormat = "hap";
    std::string profileContent = "";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyHap004
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyHap004, testing::ext::TestSize.Level1)
{
    std::string file = "";
    int64_t offset = 1397151;
    int64_t length = 23193;
    std::string fileFormat = "hap";
    std::string profileContent = "";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifySingleFile
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifySingleFile, testing::ext::TestSize.Level1)
{
    std::ifstream input;
    input.open("./codeSigning/entry-default-signed-so.hap", std::ios::binary);
    int64_t length = 4096;
    std::vector<int8_t> signature;
    int64_t merkleTreeOffset = 64;
    std::vector<int8_t> inMerkleTreeBytes;
    bool flag = VerifyCodeSignature::VerifySingleFile(input, length, signature, merkleTreeOffset, inMerkleTreeBytes);

    EXPECT_EQ(flag, false);
}
