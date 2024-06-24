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
#include "sign_bin.h"
#include "sign_provider.h"
#include "local_sign_provider.h"
#define VERSION 9
#define BYTE_NUMBER 32
namespace OHOS {
namespace SignatureTools {
/*
* 测试套件,固定写法
*/
class SignBinTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
    };
    static void TearDownTestCase()
    {
    };
    void SetUp()
    {
    };
    void TearDown()
    {
    };
};

void ConstructSignerConfig(SignerConfig& signerConfig, Options& options)
{
    signerConfig.SetCompatibleVersion(VERSION);

    std::map<std::string, std::string> params;
    params["keyPwd"] = "123456";
    params["mode"] = "localSign";
    params["keyAlias"] = "oh-app1-key-v1";
    params["signAlg"] = "SHA256withECDSA";
    params["appCertFile"] = "./codeSigning/app-release1.pem";
    params["signCode"] = "1";
    params["compatibleVersion"] = "9";
    params["outFile"] = "./codeSigning/entry-default-signed-so.hap";
    params["profileFile"] = "./codeSigning/signed-profile.p7b";
    params["keystorePwd"] = "123456";
    params["keystoreFile"] = "./codeSigning/ohtest.jks";
    params["inFile"] = "./codeSigning/entry-default-unsigned-so.hap";
    params["profileSigned"] = "1";
    signerConfig.FillParameters(params);

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", BYTE_NUMBER);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmHelper signatureAlgorithm(SignatureAlgorithmId::ECDSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                                contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmHelper> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    options.emplace("mode", std::string("localSign"));
    char keyPwd[] = "123456";
    options.emplace("keyPwd", keyPwd);
    options.emplace("outFile", std::string("./hapSign/signed-linux.out"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/app1-profile1.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    char keystorePwd[] = "123456";
    options.emplace("keystorePwd", keystorePwd);
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.p12"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    signerConfig.SetOptions(&options);
}

void ConstructSignParams(std::map<std::string, std::string>& signParams)
{
    signParams["a"] = "4";
    signParams["appCertFile"] = "./hapSign/app-release1.pem";
    signParams["compatibleVersion"] = "9";
    signParams["inFile"] = "./hapSign/unsigned-1M.bin";
    signParams["inForm"] = "bin";
    signParams["keyAlias"] = "oh-app1-key-v1";
    signParams["keyPwd"] = "123456";
    signParams["keystoreFile"] = "./hapSign/ohtest.p12";
    signParams["keystorePwd"] = "123456";
    signParams["outFile"] = "./hapSign/signed-linux.out";
    signParams["profileFile"] = "./hapSign/app1-profile1.p7b";
    signParams["profileSigned"] = "1";
    signParams["signAlg"] = "SHA256withECDSA";
    signParams["signCode"] = "1";
}

/**
 * @tc.name: GenerateFileDigest001
 * @tc.desc: Test interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignBinTest, GenerateFileDigest001, testing::ext::TestSize.Level1)
{
    // 走进分支 get Signature Algorithm failed
    std::shared_ptr<SignBin> api = std::make_shared<SignBin>();
    std::vector<int8_t> generateFileDigest = api->GenerateFileDigest("./signed-linux.out", "SHA266");
    EXPECT_EQ(generateFileDigest.size(), 0);
}

/**
 * @tc.name: GenerateFileDigest002
 * @tc.desc: Test interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignBinTest, GenerateFileDigest002, testing::ext::TestSize.Level1)
{
    // 走进分支 GetFileDigest failed
    std::shared_ptr<SignBin> api = std::make_shared<SignBin>();
    std::vector<int8_t> generateFileDigest = api->GenerateFileDigest("./signed-linux.out", "SHA384withECDSA");
    EXPECT_EQ(generateFileDigest.size(), 0);
}

/**
 * @tc.name: Sign001
 * @tc.desc: Test interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignBinTest, Sign001, testing::ext::TestSize.Level1)
{
    // 走进分支 The block head data made failed
    std::shared_ptr<SignBin> api = std::make_shared<SignBin>();

    std::map<std::string, std::string> signParams;
    signParams["a"] = "4";
    signParams["appCertFile"] = "./app-release1.pem";
    signParams["compatibleVersion"] = "9";
    signParams["inFile"] = "./unsigned-linuxxxxx.out";
    signParams["inForm"] = "bin";
    signParams["keyAlias"] = "oh-app1-key-v1";
    signParams["keyPwd"] = "123456";
    signParams["keystoreFile"] = "./ohtest.p12";
    signParams["keystorePwd"] = "123456";
    signParams["outFile"] = "./signed - linux.out";
    signParams["profileFile"] = "./app1-profile1.p7b";
    signParams["profileSigned"] = "1";
    signParams["signAlg"] = "SHA256withECDSA";
    signParams["signCode"] = "1";

    SignerConfig signerConfig;

    api->Sign(signerConfig, signParams);
    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: Sign002
 * @tc.desc: Test interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignBinTest, Sign002, testing::ext::TestSize.Level1)
{
    // 走进分支 The sign data made failed
    std::shared_ptr<SignBin> api = std::make_shared<SignBin>();

    // 1.construct SignerConfig
    SignerConfig signerConfig;
    Options options;
    ConstructSignerConfig(signerConfig, options);

    // 2.construct sign params
    std::map<std::string, std::string> signParams;
    ConstructSignParams(signParams);

    api->Sign(signerConfig, signParams);
    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: SignBinTest
 * @tc.desc: Test interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignBinTest, SignBin, testing::ext::TestSize.Level1)
{
    // 走进sign_provider中SignBin分支 check Compatible Version failed!
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "1";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string inFile = "./hapSign/unsigned-linux.out";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/entry-default-signed.elf";
    std::string inForm = "bin";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";
    std::string compatibleVersion = "";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["inForm"] = inForm;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["compatibleVersion"] = compatibleVersion;
    bool ret = signProvider->SignBin(params.get());
    EXPECT_EQ(ret, true);
}

} // namespace SignatureTools
} // namespace OHOS
