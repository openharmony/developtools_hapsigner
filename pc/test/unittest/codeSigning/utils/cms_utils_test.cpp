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
#include <gtest/gtest.h>
#include "cms_utils.h"
#include "verify_code_signature.h"

using namespace OHOS::SignatureTools;

/*
 * 测试套件,固定写法
 */
class CmsUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: CheckOwnerID001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CmsUtilsTest, CheckOwnerID001, testing::ext::TestSize.Level1)
{
    // 走进分支 if (p7 == nullptr)
    const std::string signature;
    const std::string profileOwnerID;
    const std::string profileType = "debug";
    bool flag = CmsUtils::CheckOwnerID(signature, profileOwnerID, profileType);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: CheckOwnerID002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CmsUtilsTest, CheckOwnerID002, testing::ext::TestSize.Level1)
{
    // 走进 for 下的 if ("debug" == profileType) 分支
    std::string signature;
    FileUtils::ReadFile("./codeSigning/signed-profile.p7b", signature);

    const std::string profileOwnerID = "xxx";
    const std::string profileType = "debug";
    bool flag = CmsUtils::CheckOwnerID(signature, profileOwnerID, profileType);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: CheckOwnerID003
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CmsUtilsTest, CheckOwnerID003, testing::ext::TestSize.Level1)
{
    // 走进 for 下的 if (ownerID.empty()) 分支
    std::string signature;
    FileUtils::ReadFile("./codeSigning/signed-profile.p7b", signature);

    const std::string profileOwnerID;
    const std::string profileType = "release";
    bool flag = CmsUtils::CheckOwnerID(signature, profileOwnerID, profileType);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: CheckOwnerID004
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CmsUtilsTest, CheckOwnerID004, testing::ext::TestSize.Level1)
{
    // 走进 for 下的 else 分支
    std::string signature;
    FileUtils::ReadFile("./codeSigning/signed-profile.p7b", signature);

    const std::string profileOwnerID = "007";
    const std::string profileType = "release";
    bool flag = CmsUtils::CheckOwnerID(signature, profileOwnerID, profileType);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyHap
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CmsUtilsTest, VerifyHap, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/entry-default-signed-so.hap";
    int64_t offset = 1397151;
    int64_t length = 23221;
    std::string fileFormat = "hap";
    std::string profileContent = "";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: CreateNIDFromOID
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CmsUtilsTest, CreateNIDFromOID, testing::ext::TestSize.Level1)
{
    std::string oid;
    std::string shortName;
    std::string longName;
    int nID = CmsUtils::CreateNIDFromOID(oid, shortName, longName);

    EXPECT_EQ(nID, 0);
}

/**
 * @tc.name: VerifySignDataWithUnsignedDataDigest
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CmsUtilsTest, VerifySignDataWithUnsignedDataDigest, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> unsignedDataDigest;
    std::vector<int8_t> signedData;
    bool flag = CmsUtils::VerifySignDataWithUnsignedDataDigest(unsignedDataDigest, signedData);

    EXPECT_EQ(flag, false);
}
