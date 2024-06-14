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

#include "verify_bin.h"

using namespace OHOS::SignatureTools;

class VerifyBinTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: Verify001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, Verify001, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: Verify002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, Verify002, testing::ext::TestSize.Level1)
{
    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(nullptr);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: Verify003
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, Verify003, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.bin"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: Verify004
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, Verify004, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: Verify005
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, Verify005, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: Verify006
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, Verify006, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed111.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: Verify007
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, Verify007, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-unsigned.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: Verify008
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, Verify008, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/readonly.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: Verify009
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, Verify009, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: Verify010
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, Verify010, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err2.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    EXPECT_EQ(flag, false);
}