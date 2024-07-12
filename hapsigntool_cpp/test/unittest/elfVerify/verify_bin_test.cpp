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
#include "sign_bin.h"
#include "hash_utils.h"
#include "packet_helper.h"

extern char* GetSignedBinErrPacket(void);
extern char* GetSignedBinErr2Packet(void);
extern char* GetSignedBinErr3Packet(void);
extern char* GetSignedBinPacket(void);
extern char* GetUnsignedBinPacket(void);

using namespace OHOS::SignatureTools;

class VerifyBinTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void VerifyBinTest::SetUpTestCase(void)
{
    (void)Base64DecodeStringToFile(GetSignedBinErrPacket(), "./elfVerify/linuxout-signed-err.bin");
    (void)Base64DecodeStringToFile(GetSignedBinErr2Packet(), "./elfVerify/linuxout-signed-err2.bin");
    (void)Base64DecodeStringToFile(GetSignedBinErr3Packet(), "./elfVerify/linuxout-signed-err3.bin");
    (void)Base64DecodeStringToFile(GetSignedBinPacket(), "./elfVerify/linuxout-signed.bin");
    (void)Base64DecodeStringToFile(GetUnsignedBinPacket(), "./elfVerify/linuxout-unsigned.bin");
}

void VerifyBinTest::TearDownTestCase(void)
{
    (void)remove("./elfVerify/linuxout-signed-err.bin");
    (void)remove("./elfVerify/linuxout-signed-err2.bin");
    (void)remove("./elfVerify/linuxout-signed-err3.bin");
    (void)remove("./elfVerify/linuxout-signed.bin");
    (void)remove("./elfVerify/linuxout-unsigned.bin");
}

void VerifyBinTest::SetUp()
{
}

void VerifyBinTest::TearDown()
{
}

static const std::map<std::string, std::string> PARAMS = { {"keyPwd", "123456"},
                                                           {"mode", "localSign"},
                                                           {"keyAlias", "oh-app1-key-v1"},
                                                           {"signAlg", "SHA256withECDSA"},
                                                           {"appCertFile", "./hapSign/app-release1.pem"},
                                                           {"signCode", "1"},
                                                           {"compatibleVersion", "9"},
                                                           {"keystorePwd", "123456"},
                                                           {"outFile", "./elfVerify/linuxout-signed.bin"},
                                                           {"profileSigned", "1"},
                                                           {"profileFile", "./hapSign/signed-profile.p7b"},
                                                           {"keystoreFile", "./hapSign/ohtest.jks"},
                                                           {"inFile", "./elfVerify/linuxout-unsigned.bin"} };

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

    EXPECT_EQ(flag, true);
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

/**
 * @tc.name: Verify011
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, Verify011, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err3.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: SignBin001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, SignBin001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignBin> api = std::make_shared<SignBin>();
    std::map<std::string, std::string> signParams;
    signParams["a"] = "4";
    signParams["appCertFile"] = "./hapSign/app-release1.pem";
    signParams["compatibleVersion"] = "9";
    signParams["inFile"] = "./elfVerify/linuxout-unsigned.bin";
    signParams["inForm"] = "bin";
    signParams["keyAlias"] = "oh-app1-key-v1";
    signParams["keyPwd"] = "123456";
    signParams["keystoreFile"] = "./hapSign/ohtest.p12";
    signParams["keystorePwd"] = "123456";
    signParams["outFile"] = "./elfVerify/linuxout-signed.bin";
    signParams["profileFile"] = "./hapSign/signed-profile.p7b";
    signParams["profileSigned"] = "1";
    signParams["signAlg"] = "SHA256withECDSA";
    signParams["signCode"] = "1";

    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);
    signerConfig.FillParameters(PARAMS);

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmHelper signatureAlgorithm(SignatureAlgorithmId::ECDSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                                contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmHelper> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./elfVerify/linuxout-signed.bin"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.p12"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./elfVerify/linuxout-unsigned.bin"));
    signerConfig.SetOptions(&options);
    bool flag = api->Sign(signerConfig, signParams);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: GetHashAlgsId001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, GetHashAlgsId001, testing::ext::TestSize.Level1)
{
    int algId = HashUtils::GetHashAlgsId("SHA-224");

    EXPECT_EQ(algId, 5);
}

/**
 * @tc.name: GetHashAlgsId002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, GetHashAlgsId002, testing::ext::TestSize.Level1)
{
    int algId = HashUtils::GetHashAlgsId("SHA-256");

    EXPECT_EQ(algId, 6);
}

/**
 * @tc.name: GetHashAlgsId003
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, GetHashAlgsId003, testing::ext::TestSize.Level1)
{
    int algId = HashUtils::GetHashAlgsId("SHA-384");

    EXPECT_EQ(algId, 7);
}

/**
 * @tc.name: GetHashAlgsId004
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, GetHashAlgsId004, testing::ext::TestSize.Level1)
{
    int algId = HashUtils::GetHashAlgsId("SHA-512");

    EXPECT_EQ(algId, 8);
}

/**
 * @tc.name: GetHashAlgName001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, GetHashAlgName001, testing::ext::TestSize.Level1)
{
    std::string alg = HashUtils::GetHashAlgName(5);
    int size = alg.size();
    EXPECT_NE(size, 0);
}

/**
 * @tc.name: GetHashAlgName002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, GetHashAlgName002, testing::ext::TestSize.Level1)
{
    std::string alg = HashUtils::GetHashAlgName(6);
    int size = alg.size();
    EXPECT_NE(size, 0);
}

/**
 * @tc.name: GetHashAlgName003
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, GetHashAlgName003, testing::ext::TestSize.Level1)
{
    std::string alg = HashUtils::GetHashAlgName(7);
    int size = alg.size();
    EXPECT_NE(size, 0);
}

/**
 * @tc.name: GetHashAlgName004
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, GetHashAlgName004, testing::ext::TestSize.Level1)
{
    std::string alg = HashUtils::GetHashAlgName(8);
    int size = alg.size();
    EXPECT_NE(size, 0);
}

/**
 * @tc.name: GetDigestFromBytes001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, GetDigestFromBytes001, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> fileBytes;
    int64_t length = 0;
    std::string algName = "SHA-256";
    std::vector<int8_t> dig = HashUtils::GetDigestFromBytes(fileBytes, length, algName);
    int size = dig.size();

    EXPECT_EQ(size, 0);
}

/**
 * @tc.name: GetDigestFromBytes002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyBinTest, GetDigestFromBytes002, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> fileBytes = { 1, 1 };
    int64_t length = 0;
    std::string algName = "SHA-256";
    std::vector<int8_t> dig = HashUtils::GetDigestFromBytes(fileBytes, length, algName);
    int size = dig.size();

    EXPECT_EQ(size, 0);
}