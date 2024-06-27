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

#include "sign_elf.h"
#include "code_signing.h"
#include "packet_helper.h"

extern char* GetUnsignedLinuxout(void);

namespace OHOS {
namespace SignatureTools {
class SignElfTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        (void)Base64DecodeStringToFile(GetUnsignedLinuxout(), "./hapSign/unsigned-linux.out");
    };
    static void TearDownTestCase()
    {
        (void)remove("./hapSign/unsigned-linux.out");
    };
    void SetUp()
    {
    };
    void TearDown()
    {
    };
};

class CodeSigningTest : public testing::Test {
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

void SetParamsMap(std::map<std::string, std::string>& params)
{
    params["keyPwd"] = "123456";
    params["mode"] = "localSign";
    params["keyAlias"] = "oh-app1-key-v1";
    params["signAlg"] = "SHA256withECDSA";
    params["appCertFile"] = "./hapSign/app-release1.pem";
    params["signCode"] = "1";
    params["compatibleVersion"] = "9";
    params["outFile"] = "./hapSign/entry-default-signed.elf";
    params["profileFile"] = "./hapSign/signed-profile.p7b";
    params["keystorePwd"] = "123456";
    params["keystoreFile"] = "./hapSign/ohtest.jks";
    params["inFile"] = "./hapSign/unsigned-linux.out";
    params["profileSigned"] = "1";
    params["inForm"] = "elf";
    params["profileContent"] = "({\"bundle-info\":{\"app-feature\":\"hos_system_app\","
        "\"bundle-name\":\"com.OpenHarmony.app.test\","
        "\"developer-id\":\"OpenHarmony\",\"development-certificate\":"
        "\"-----BEGIN CERTIFICATE-----\\n"
        "MIICMzCCAbegAwIBAgIEaOC/zDAMBggqhkjOPQQDAwUAMGMxCzAJBgNVBAYTAkNO\\n"
        "MRQwEgYDVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVh\\n"
        "bTEjMCEGA1UEAxMaT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gQ0EwHhcNMjEwMjAy\\n"
        "MTIxOTMxWhcNNDkxMjMxMTIxOTMxWjBoMQswCQYDVQQGEwJDTjEUMBIGA1UEChML\\n"
        "T3Blbkhhcm1vbnkxGTAXBgNVBAsTEE9wZW5IYXJtb255IFRlYW0xKDAmBgNVBAMT\\n"
        "H09wZW5IYXJtb255IEFwcGxpY2F0aW9uIFJlbGVhc2UwWTATBgcqhkjOPQIBBggq\\n"
        "hkjOPQMBBwNCAATbYOCQQpW5fdkYHN45v0X3AHax12jPBdEDosFRIZ1eXmxOYzSG\\n"
        "JwMfsHhUU90E8lI0TXYZnNmgM1sovubeQqATo1IwUDAfBgNVHSMEGDAWgBTbhrci\\n"
        "FtULoUu33SV7ufEFfaItRzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFPtxruhl\\n"
        "cRBQsJdwcZqLu9oNUVgaMAwGCCqGSM49BAMDBQADaAAwZQIxAJta0PQ2p4DIu/ps\\n"
        "LMdLCDgQ5UH1l0B4PGhBlMgdi2zf8nk9spazEQI/0XNwpft8QAIwHSuA2WelVi/o\\n"
        "zAlF08DnbJrOOtOnQq5wHOPlDYB4OtUzOYJk9scotrEnJxJzGsh/\\n"
        "-----END CERTIFICATE-----\\n"
        "\"}, \"debug-info\":{\"device-id-type\":\"udid\",\"device-ids\":["
        "\"69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42\","
        "\"7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865\"]},"
        "\"issuer\":\"pki_internal\",\"permissions\":{\"restricted-permissions\":[\"\"]},"
        "\"type\":\"debug\",\"uuid\":\"fe686e1b-3770-4824 - a938 - 961b140a7c98\","
        "\"validity\":{\"not-after\":1705127532,\"not-before\":1610519532},"
        "\"version-code\":1,\"version-name\":"
        "\"1.0.0\"})";
}

void SetOptions(Options* options)
{
    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "1";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string inFile = "./hapSign/unsigned-linux.out";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/entry-default-signed.elf";
    std::string inForm = "elf";
    static char keyPwd[] = "123456";
    static char keystorePwd[] = "123456";

    (*options)["mode"] = "localSign";
    (*options)["keyAlias"] = keyAlias;
    (*options)["signAlg"] = signAlg;
    (*options)["signCode"] = signCode;
    (*options)["appCertFile"] = appCertFile;
    (*options)["profileFile"] = profileFile;
    (*options)["inFile"] = inFile;
    (*options)["keystoreFile"] = keystoreFile;
    (*options)["outFile"] = outFile;
    (*options)["inForm"] = inForm;
    (*options)["keyPwd"] = keyPwd;
    (*options)["keystorePwd"] = keystorePwd;
}

/**
 * @tc.name: sign001
 * @tc.desc: Test function of SignElf::sign() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignElfTest, Sign001, testing::ext::TestSize.Level1)
{
    // success
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

    std::map<std::string, std::string> params;
    SetParamsMap(params);
    signerConfig.FillParameters(params);

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmHelper signatureAlgorithm(SignatureAlgorithmId::ECDSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                                contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmHelper> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    std::shared_ptr<Options> options = std::make_shared<Options>();
    SetOptions(options.get());
    signerConfig.SetOptions(options.get());

    signerConfig.GetSigner();
    bool ret = SignElf::Sign(signerConfig, params);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: sign002
 * @tc.desc: Test function of SignElf::sign() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignElfTest, Sign002, testing::ext::TestSize.Level1)
{
    // failed: inFile is null
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

    std::map<std::string, std::string> params;
    SetParamsMap(params);
    params["inFile"] = "./hapSign/unsigned-linux-no.out";
    signerConfig.FillParameters(params);

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmHelper signatureAlgorithm(SignatureAlgorithmId::ECDSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                                contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmHelper> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    std::shared_ptr<Options> options = std::make_shared<Options>();
    SetOptions(options.get());
    (*options)["inFile"] = "./hapSign/unsigned-linux-no.out";
    signerConfig.SetOptions(options.get());

    signerConfig.GetSigner();
    bool ret = SignElf::Sign(signerConfig, params);

    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: sign003
 * @tc.desc: Test function of SignElf::sign() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignElfTest, Sign003, testing::ext::TestSize.Level1)
{
    // failed:profileFile is null
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

    std::map<std::string, std::string> params;
    SetParamsMap(params);
    params["profileFile"] = "./hapSign/signed-profile-no.p7b";
    signerConfig.FillParameters(params);

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmHelper signatureAlgorithm(SignatureAlgorithmId::ECDSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                                contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmHelper> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    std::shared_ptr<Options> options = std::make_shared<Options>();
    SetOptions(options.get());
    (*options)["profileFile"] = "./hapSign/signed-profile-no.p7b";
    signerConfig.SetOptions(options.get());

    signerConfig.GetSigner();
    bool ret = SignElf::Sign(signerConfig, params);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: sign004
 * @tc.desc: Test function of SignElf::sign() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignElfTest, Sign004, testing::ext::TestSize.Level1)
{
    // failed:outFile is null
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

    std::map<std::string, std::string> params;
    SetParamsMap(params);
    params["outFile"] = "./hapSign_test/entry-default-signed.elf";
    signerConfig.FillParameters(params);

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmHelper signatureAlgorithm(SignatureAlgorithmId::ECDSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                                contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmHelper> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    std::shared_ptr<Options> options = std::make_shared<Options>();
    SetOptions(options.get());
    (*options)["outFile"] = "./hapSign_test/entry-default-signed.elf";
    signerConfig.SetOptions(options.get());

    signerConfig.GetSigner();
    bool ret = SignElf::Sign(signerConfig, params);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: sign005
 * @tc.desc: Test function of SignElf::sign() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(SignElfTest, Sign005, testing::ext::TestSize.Level1)
{
    // failed:signCode is 0
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

    std::map<std::string, std::string> params;
    SetParamsMap(params);
    params["signCode"] = "0";
    signerConfig.FillParameters(params);

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmHelper signatureAlgorithm(SignatureAlgorithmId::ECDSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                                contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmHelper> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    std::shared_ptr<Options> options = std::make_shared<Options>();
    SetOptions(options.get());
    (*options)["signCode"] = "0";
    signerConfig.SetOptions(options.get());

    signerConfig.GetSigner();
    bool ret = SignElf::Sign(signerConfig, params);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetCodeSignBlock001
 * @tc.desc: Test function of CodeSigning::GetCodeSignBlock() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSigningTest, GetCodeSignBlock001, testing::ext::TestSize.Level1)
{
    CodeSigning object;
    std::string input = "./hapSign_test/entry-default-signed.elf";
    int64_t offset = 0;
    std::string inForm = "elf";
    std::string profileContent = "";
    ZipSigner zip;
    std::vector<int8_t> ret;
    bool result = object.GetCodeSignBlock(input, offset, inForm, profileContent, zip, ret);
    EXPECT_EQ(result, true);
}

}
}
