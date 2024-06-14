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

#include "verify_elf.h"
#include "hw_block_data.h"
#include "sign_provider.h"
#include "verify_hap.h"

using namespace OHOS::SignatureTools;

class VerifyElfTest : public testing::Test {
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
HWTEST_F(VerifyElfTest, Verify001, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

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
HWTEST_F(VerifyElfTest, Verify002, testing::ext::TestSize.Level1)
{
    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(nullptr);

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
HWTEST_F(VerifyElfTest, Verify003, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

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
HWTEST_F(VerifyElfTest, Verify004, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

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
HWTEST_F(VerifyElfTest, Verify005, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

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
HWTEST_F(VerifyElfTest, Verify006, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed111.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

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
HWTEST_F(VerifyElfTest, Verify007, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-unsigned.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

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
HWTEST_F(VerifyElfTest, Verify008, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/readonly.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

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
HWTEST_F(VerifyElfTest, Verify009, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

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
HWTEST_F(VerifyElfTest, Verify010, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err2.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: Verify011
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, Verify011, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err3.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: Verify012
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, Verify012, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err4.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: CheckParams
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, CheckParams, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    bool flag = VerifyElf::CheckParams(&options);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: CheckSignFile
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, CheckSignFile, testing::ext::TestSize.Level1)
{
    std::string file = "./elfVerify/linuxout-signed.elf";

    bool flag = VerifyElf::CheckSignFile(file);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: GetSignBlockData
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, GetSignBlockData, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> bytes = { 1, 1, 1, 1, 1, 1, 1, 1 };
    HwBlockData hwBlockData(0, 0);

    bool flag = VerifyElf::GetSignBlockData(bytes, hwBlockData, "elf");

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: GetSignBlockInfo
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, GetSignBlockInfo, testing::ext::TestSize.Level1)
{
    std::string file = "./elfVerify/linuxout-signed.elf";
    SignBlockInfo signBlockInfo(false);

    bool flag = VerifyElf::GetSignBlockInfo(file, signBlockInfo, "elf");

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: GetFileDigest
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, GetFileDigest, testing::ext::TestSize.Level1)
{
    std::string file = "./elfVerify/linuxout-signed.elf";
    SignBlockInfo signBlockInfo(false);
    VerifyElf::GetSignBlockInfo(file, signBlockInfo, "elf");
    std::vector<int8_t> fileBytes = { 1, 1, 1, 1, 1, 1, 1, 1 };
    std::vector<int8_t> signatrue = { 1, 1, 1, 1, 1, 1, 1, 1 };

    bool flag = VerifyElf::GetFileDigest(fileBytes, signatrue, signBlockInfo);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: GetRawContent
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, GetRawContent, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> contentVec = { 1, 1, 1, 1, 1, 1, 1, 1 };
    std::string rawContent;

    bool flag = VerifyElf::GetRawContent(contentVec, rawContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyP7b
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, VerifyP7b, testing::ext::TestSize.Level1)
{
    std::unordered_map<signed char, SigningBlock> signBlockMap;
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));
    Pkcs7Context pkcs7Context;
    HapVerifyResult verifyResult;
    std::string profileJson;

    bool flag = VerifyElf::VerifyP7b(signBlockMap, &options, pkcs7Context, verifyResult, profileJson);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: SignElf001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, SignElf001, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("signCode", std::string("1"));
    options.emplace("inForm", std::string("elf"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: SignElf002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, SignElf002, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("signCode", std::string("0"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: SignElf003
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, SignElf003, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("signCode", std::string("2"));
    options.emplace("inForm", std::string("elf"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: SignElf004
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, SignElf004, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/phone-default-unsigned"));
    options.emplace("signCode", std::string("1"));
    options.emplace("inForm", std::string("elf"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: SignElf005
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, SignElf005, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux111.out"));
    options.emplace("signCode", std::string("1"));
    options.emplace("inForm", std::string("elf"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: SignElf006
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, SignElf006, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA512withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("signCode", std::string("1"));
    options.emplace("inForm", std::string("elf"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: SignElf007
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, SignElf007, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("signCode", std::string("1"));
    options.emplace("inForm", std::string("elf"));
    options.emplace("compatibleVersion", std::string("a"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: SignBin001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, SignBin001, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA512withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("inForm", std::string("bin"));

    SignProvider signProvider;
    bool flag = signProvider.SignBin(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyElfProfile001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, VerifyElfProfile001, testing::ext::TestSize.Level1)
{
    Options options;
    std::vector<int8_t> profileData = { 1, 1, 1, 1, 1, 1, 1, 1 };
    HapVerifyResult result;
    Pkcs7Context pkcs7Context;
    VerifyHap verifyHap;
    int32_t flag = verifyHap.VerifyElfProfile(profileData, result, &options, pkcs7Context);

    EXPECT_NE(flag, 0);
}

/**
 * @tc.name: WriteVerifyOutput001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, WriteVerifyOutput001, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    SignBlockInfo signBlockInfo(false);
    VerifyElf::GetSignBlockInfo("./elfVerify/linuxout-signed.elf", signBlockInfo, "elf");
    std::unordered_map<signed char, SigningBlock> signBlockMap = signBlockInfo.GetSignBlockMap();
    SigningBlock profileSign = signBlockMap.find(2)->second;
    std::vector<int8_t> profileByte = profileSign.GetValue();
    HapVerifyResult result;
    Pkcs7Context pkcs7Context;
    VerifyHap hapVerifyV2;
    hapVerifyV2.VerifyElfProfile(profileByte, result, &options, pkcs7Context);
    int32_t flag = hapVerifyV2.WriteVerifyOutput(pkcs7Context, &options);

    EXPECT_NE(flag, 0);
}

/**
 * @tc.name: WriteVerifyOutput002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyElfTest, WriteVerifyOutput002, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));

    SignBlockInfo signBlockInfo(false);
    VerifyElf::GetSignBlockInfo("./elfVerify/linuxout-signed.elf", signBlockInfo, "elf");
    std::unordered_map<signed char, SigningBlock> signBlockMap = signBlockInfo.GetSignBlockMap();
    SigningBlock profileSign = signBlockMap.find(2)->second;
    std::vector<int8_t> profileByte = profileSign.GetValue();
    HapVerifyResult result;
    Pkcs7Context pkcs7Context;
    VerifyHap hapVerifyV2;
    hapVerifyV2.VerifyElfProfile(profileByte, result, &options, pkcs7Context);
    int32_t flag = hapVerifyV2.WriteVerifyOutput(pkcs7Context, &options);

    EXPECT_NE(flag, 0);
}