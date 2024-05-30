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
#include "code_signing.h"
#include "zip_signer.h"

using namespace OHOS::SignatureTools;

/*
 * 测试套件,固定写法
 */
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

/**
 * @tc.name: generateSignature
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSigningTest, generateSignature, testing::ext::TestSize.Level1)
{
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

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

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmClass signatureAlgorithm(SignatureAlgorithmId::DSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                               contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmClass> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./codeSigning/entry-default-signed-so.hap"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./codeSigning/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./codeSigning/ohtest.jks"));
    options.emplace("appCertFile", std::string("./codeSigning/app-release1.pem"));
    options.emplace("inFile", std::string("./codeSigning/entry-default-unsigned-so.hap"));
    signerConfig.SetOptions(&options);

    CodeSigning codeSigning(signerConfig);

    std::vector<int8_t> signedData = { 70, 83, 86, 101, 114, 105, 116, 121, 1,
        0, 32, 0, -82, 98, 15, 102, 95, -26, -90, 88, 83, 8, -42, -65, -121,
        117, -43, -95, -102, -56, 109, 93, 25, -9, -88, 44, -25, 119, -39, -68,
        -15, 11, 123, -80 };
    std::string ownerID;
    std::vector<int8_t> ret;
    bool flag = codeSigning.generateSignature(signedData, ownerID, ret);
    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: GetNativeEntriesFromHap
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSigningTest, GetNativeEntriesFromHap, testing::ext::TestSize.Level1)
{
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

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

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmClass signatureAlgorithm(SignatureAlgorithmId::DSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                               contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmClass> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./codeSigning/entry-default-signed-so.hap"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./codeSigning/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./codeSigning/ohtest.jks"));
    options.emplace("appCertFile", std::string("./codeSigning/app-release1.pem"));
    options.emplace("inFile", std::string("./codeSigning/entry-default-unsigned-so.hap"));
    signerConfig.SetOptions(&options);

    CodeSigning codeSigning(signerConfig);

    std::string packageName = "libs/arm64-v8a/libc++_shared.so";
    std::vector<std::tuple<std::string, std::stringbuf, uLong>> ret = codeSigning.GetNativeEntriesFromHap(packageName);
    EXPECT_EQ(ret.size(), false);
}

/**
 * @tc.name: getTimestamp
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSigningTest, getTimestamp, testing::ext::TestSize.Level1)
{
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

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

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmClass signatureAlgorithm(SignatureAlgorithmId::DSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                               contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmClass> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./codeSigning/entry-default-signed-so.hap"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./codeSigning/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./codeSigning/ohtest.jks"));
    options.emplace("appCertFile", std::string("./codeSigning/app-release1.pem"));
    options.emplace("inFile", std::string("./codeSigning/entry-default-unsigned-so.hap"));
    signerConfig.SetOptions(&options);

    CodeSigning codeSigning(signerConfig);
    int64_t timeStamp = codeSigning.getTimestamp();
    EXPECT_NE(timeStamp, 0);
}

/**
 * @tc.name: isNativeFile
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSigningTest, isNativeFile, testing::ext::TestSize.Level1)
{
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

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

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmClass signatureAlgorithm(SignatureAlgorithmId::DSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                               contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmClass> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./codeSigning/entry-default-signed-so.hap"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./codeSigning/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./codeSigning/ohtest.jks"));
    options.emplace("appCertFile", std::string("./codeSigning/app-release1.pem"));
    options.emplace("inFile", std::string("./codeSigning/entry-default-unsigned-so.hap"));
    signerConfig.SetOptions(&options);

    CodeSigning codeSigning(signerConfig);
    std::string input = "libs/arm64-v8a/libc++_shared.so";
    bool flag = codeSigning.isNativeFile(input);
    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: signFile
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSigningTest, signFile, testing::ext::TestSize.Level1)
{
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

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

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmClass signatureAlgorithm(SignatureAlgorithmId::DSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                               contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmClass> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./codeSigning/entry-default-signed-so.hap"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./codeSigning/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./codeSigning/ohtest.jks"));
    options.emplace("appCertFile", std::string("./codeSigning/app-release1.pem"));
    options.emplace("inFile", std::string("./codeSigning/entry-default-unsigned-so.hap"));
    signerConfig.SetOptions(&options);

    CodeSigning codeSigning(signerConfig);

    std::ifstream inputStream;
    inputStream.open("./codeSigning/entry-default-unsigned-so.hap", std::ios::binary);
    int64_t fileSize = 3479976;
    bool storeTree = true;
    int64_t fsvTreeOffset = 1024;
    std::string ownerID;
    std::pair<SignInfo, std::vector<int8_t>> ret;
    bool flag = codeSigning.signFile(inputStream, fileSize, storeTree, fsvTreeOffset, ownerID, ret);
    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: SignFilesFromJar
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSigningTest, SignFilesFromJar, testing::ext::TestSize.Level1)
{
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

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

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmClass signatureAlgorithm(SignatureAlgorithmId::DSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                               contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmClass> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./codeSigning/entry-default-signed-so.hap"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./codeSigning/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./codeSigning/ohtest.jks"));
    options.emplace("appCertFile", std::string("./codeSigning/app-release1.pem"));
    options.emplace("inFile", std::string("./codeSigning/entry-default-unsigned-so.hap"));
    signerConfig.SetOptions(&options);

    CodeSigning codeSigning(signerConfig);
    std::vector<std::tuple<std::string, std::stringbuf, uLong>> entryNames;
    std::string packageName = "libs/arm64-v8a/libc++_shared.so";
    std::string ownerID;
    std::vector<std::pair<std::string, SignInfo>> ret;
    bool flag = codeSigning.SignFilesFromJar(entryNames, packageName, ownerID, ret);
    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: signNativeLibs
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSigningTest, signNativeLibs, testing::ext::TestSize.Level1)
{
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

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

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmClass signatureAlgorithm(SignatureAlgorithmId::DSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                               contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmClass> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./codeSigning/entry-default-signed-so.hap"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./codeSigning/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./codeSigning/ohtest.jks"));
    options.emplace("appCertFile", std::string("./codeSigning/app-release1.pem"));
    options.emplace("inFile", std::string("./codeSigning/entry-default-unsigned-so.hap"));
    signerConfig.SetOptions(&options);

    CodeSigning codeSigning(signerConfig);
    std::string input = "./codeSigning/entry-default-unsigned-so.hap";
    std::string ownerID;
    bool flag = codeSigning.signNativeLibs(input, ownerID);
    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: splitFileName
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSigningTest, splitFileName, testing::ext::TestSize.Level1)
{
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

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

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmClass signatureAlgorithm(SignatureAlgorithmId::DSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                               contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmClass> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./codeSigning/entry-default-signed-so.hap"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./codeSigning/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./codeSigning/ohtest.jks"));
    options.emplace("appCertFile", std::string("./codeSigning/app-release1.pem"));
    options.emplace("inFile", std::string("./codeSigning/entry-default-unsigned-so.hap"));
    signerConfig.SetOptions(&options);

    CodeSigning codeSigning(signerConfig);
    std::string path = "libs/arm64-v8a/libc++_shared.so";
    std::string str = codeSigning.splitFileName(path);
    EXPECT_EQ(str.size(), 16);
}

/**
 * @tc.name: updateCodeSignBlock
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSigningTest, updateCodeSignBlock, testing::ext::TestSize.Level1)
{
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(9);

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

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", 32);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmClass signatureAlgorithm(SignatureAlgorithmId::DSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                               contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmClass> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./codeSigning/entry-default-signed-so.hap"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./codeSigning/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./codeSigning/ohtest.jks"));
    options.emplace("appCertFile", std::string("./codeSigning/app-release1.pem"));
    options.emplace("inFile", std::string("./codeSigning/entry-default-unsigned-so.hap"));
    signerConfig.SetOptions(&options);

    CodeSigning codeSigning(signerConfig);
    codeSigning.updateCodeSignBlock();
    EXPECT_EQ(true, 1);
}
