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
#include "hap_sign_Test.h"
#include "hap_sign_tool.h"
#include "sign_tool_service_impl.h"
#include "sign_provider.h"
#include "sign_hap.h"
#include "Local_sign_provider.h"
namespace OHOS {
    namespace SignatureTools {
        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_001, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "0";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[]  = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = api->SignHap(params.get());
            EXPECT_EQ(ret, true);
        }
        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_002, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "1";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = api->SignHap(params.get());
            EXPECT_EQ(ret, true);
        }
        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_003, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "1";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string profileSigned = "0";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["profileSigned"] = profileSigned;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = api->SignHap(params.get());
            EXPECT_EQ(ret, false);
        }
        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_004, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "1";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string profileSigned = "1";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["profileSigned"] = profileSigned;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = api->SignHap(params.get());
            EXPECT_EQ(ret, true);
        }
        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_005, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "0";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool retParam = signProvider->CheckParams(params.get());
            EXPECT_EQ(retParam, true);

            std::optional<X509_CRL*> crl = signProvider->GetCrl();
            EXPECT_EQ(crl.has_value(), false);

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, true);
        }

        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_006, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "1";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;
            bool retParam = signProvider->CheckParams(params.get());
            EXPECT_EQ(retParam, true);

            std::optional<X509_CRL*> crl = signProvider->GetCrl();
            EXPECT_EQ(crl.has_value(), false);

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, true);
        }

        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_007, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "1";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string profileSigned = "0";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["profileSigned"] = profileSigned;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;
            bool retParam = signProvider->CheckParams(params.get());
            EXPECT_EQ(retParam, true);

            std::optional<X509_CRL*> crl = signProvider->GetCrl();
            EXPECT_EQ(crl.has_value(), false);

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, false);
        }


        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_008, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
                std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "1";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string profileSigned = "1";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["profileSigned"] = profileSigned;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool retParam = signProvider->CheckParams(params.get());
            EXPECT_EQ(retParam, true);

            std::optional<X509_CRL*> crl = signProvider->GetCrl();
            EXPECT_EQ(crl.has_value(), false);

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, true);
        }


        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_009, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");

            ContentDigestAlgorithm alg = ContentDigestAlgorithm::SHA256;
            std::string algname = alg.GetDigestAlgorithm();
            EXPECT_EQ(algname, std::string("SHA-256"));
            int size = alg.GetDigestOutputByteSize();
            EXPECT_EQ(size, 256 / 8);

            ContentDigestAlgorithm alg_384 = ContentDigestAlgorithm::SHA384;
            std::string algname_384 = alg_384.GetDigestAlgorithm();
            EXPECT_EQ(algname_384, std::string("SHA-384"));
            int size384 = alg_384.GetDigestOutputByteSize();
            EXPECT_EQ(size384, 384 / 8);

            ContentDigestAlgorithm alg_512;
            alg_512 = ContentDigestAlgorithm::SHA512;
            std::string algname_512 = alg_512.GetDigestAlgorithm();
            EXPECT_EQ(algname_512, std::string("SHA-512"));
            int size512 = alg_512.GetDigestOutputByteSize();
            EXPECT_EQ(size512, 512 / 8);
        }
        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_010, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            ByteBuffer bf1("123456789", 9);
            ByteBuffer bf2("123456789", 9);
            ByteBuffer bf3("123456789", 9);
            ByteBuffer bf4("123456789", 9);
            ByteBufferDataSource ds1(bf1);
            ByteBufferDataSource ds2(bf2);
            ByteBufferDataSource ds3(bf3);

            DataSource* contents[] = { &ds1, &ds2, &ds3 };
            int32_t len = 3;

            std::vector<OptionalBlock> optionalBlocks;
            optionalBlocks.push_back({HapUtils::HAP_PROFILE_BLOCK_ID, bf4});
            ByteBuffer dig_context;

            SignatureAlgorithm algo = SignatureAlgorithm::ALGORITHM_SHA256_WITH_ECDSA;
            int32_t nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(algo);
            DigestParameter digestParam = HapSigningBlockUtils::GetDigestParameter(nId);

            bool ret = SignHap::ComputeDigests(digestParam, contents, len, optionalBlocks, dig_context);
            EXPECT_EQ(ret, true);
            std::vector<std::pair<int32_t, ByteBuffer>> contentDigests;

            ByteBuffer dig_message;
            std::pair<int32_t, ByteBuffer> nidAndcontentDigests = std::make_pair(algo, dig_context);
            contentDigests.push_back(nidAndcontentDigests);

            bool ret1 = SignHap::EncodeListOfPairsToByteArray(digestParam, contentDigests, dig_message);
            EXPECT_EQ(ret1, true);
        }
                /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_011, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "1";
            std::string appCertFile = "./hapSign/app-release-nohave.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string profileSigned = "1";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["profileSigned"] = profileSigned;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            std::optional<X509_CRL*> crl = signProvider->GetCrl();
            EXPECT_EQ(crl.has_value(), false);

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, false);
        }
        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_012, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "1";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string profileSigned = "1";
            std::string inFile = "./hapSign/nohave.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["profileSigned"] = profileSigned;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool retParam = signProvider->CheckParams(params.get());
            EXPECT_EQ(retParam, true);

            std::optional<X509_CRL*> crl = signProvider->GetCrl();
            EXPECT_EQ(crl.has_value(), false);

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, false);
        }

        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_013, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "1";
            std::string appCertFile = "./hapSign/app-release-.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string profileSigned = "1";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["profileSigned"] = profileSigned;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool retParam = signProvider->CheckParams(params.get());
            EXPECT_EQ(retParam, true);

            std::optional<X509_CRL*> crl = signProvider->GetCrl();
            EXPECT_EQ(crl.has_value(), false);

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, false);
        }

        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_014, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "1";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string profileSigned = "1";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "/d/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["profileSigned"] = profileSigned;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool retParam = signProvider->CheckParams(params.get());
            EXPECT_EQ(retParam, true);

            std::optional<X509_CRL*> crl = signProvider->GetCrl();
            EXPECT_EQ(crl.has_value(), false);

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, false);
        }

        
        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_015, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "1";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string profileSigned = "1";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-unsigned.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["profileSigned"] = profileSigned;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool retParam = signProvider->CheckParams(params.get());
            EXPECT_EQ(retParam, true);

            std::optional<X509_CRL*> crl = signProvider->GetCrl();
            EXPECT_EQ(crl.has_value(), false);

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, true);
        }


        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_016, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withEA";
            std::string signCode = "1";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string profileSigned = "1";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["profileSigned"] = profileSigned;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            std::optional<X509_CRL*> crl = signProvider->GetCrl();
            EXPECT_EQ(crl.has_value(), false);

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, false);
        }
        
        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_017, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "0";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/phone-default-unsigned";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, false);
        }


        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_018, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "0";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/phone-default-unsigned";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, false);
        }


        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_019, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "0";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/nohap.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, false);
        }

        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_020, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalJKSSignProvider>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "0";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/unsigned_with_eocd.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = signProvider->Sign(params.get());
            EXPECT_EQ(ret, false);
        }


        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_021, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "remoteSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "0";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[]  = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = api->SignHap(params.get());
            EXPECT_EQ(ret, false);
        }

        
        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_022, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "remoteResign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "0";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/phone-default-unsigned.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[]  = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = api->SignHap(params.get());
            EXPECT_EQ(ret, false);
        }

        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_023, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "0";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/phone-default-unsigned";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[]  = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = api->SignHap(params.get());
            EXPECT_EQ(ret, false);
        }

        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_024, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            ByteBuffer bf1("123456789", 9);
            ByteBuffer bf2("123456789", 9);
            ByteBuffer bf3("123456789", 9);
            ByteBuffer bf4("123456789", 9);
            ByteBufferDataSource ds1(bf1);
            ByteBufferDataSource ds2(bf2);
            ByteBufferDataSource ds3(bf3);

            DataSource* contents[] = { &ds1, &ds2, &ds3 };
            DataSource* contents_t[] = { nullptr, &ds2, &ds3 };
            int32_t len = 3;

            std::vector<OptionalBlock> optionalBlocks;
            optionalBlocks.push_back({HapUtils::HAP_PROFILE_BLOCK_ID, bf4});
            ByteBuffer dig_context;

            SignatureAlgorithm algo = SignatureAlgorithm::ALGORITHM_SHA256_WITH_ECDSA;
            int32_t nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(algo);
            DigestParameter digestParam = HapSigningBlockUtils::GetDigestParameter(nId);

            SignerConfig config;
            ByteBuffer result;
            ByteBuffer result1;
            bool ret1 = SignHap::Sign(contents, 2, config, optionalBlocks, result);
            EXPECT_EQ(ret1, false);

            ret1 = SignHap::Sign(contents_t, 3, config, optionalBlocks, result1);
            EXPECT_EQ(ret1, false);

            bool ret = SignHap::ComputeDigests(digestParam, contents_t, len, optionalBlocks, dig_context);
            EXPECT_EQ(ret, false);
            std::vector<std::pair<int32_t, ByteBuffer>> contentDigests;

            SignatureAlgorithm algo1 = SignatureAlgorithm::ALGORITHM_SHA384_WITH_ECDSA;
            ByteBuffer dig_message;
            std::pair<int32_t, ByteBuffer> nidAndcontentDigests = std::make_pair(algo1, dig_context);
            contentDigests.push_back(nidAndcontentDigests);

            ret1 = SignHap::EncodeListOfPairsToByteArray(digestParam, contentDigests, dig_message);
            EXPECT_EQ(ret1, false);
        }

        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_025, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "0";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/phone-default.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[]  = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = api->SignHap(params.get());
            EXPECT_EQ(ret, false);
        }

        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_026, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256withECDSA";
            std::string signCode = "0";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/unsigned_with_cd_and_eocd.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[]  = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = api->SignHap(params.get());
            EXPECT_EQ(ret, false);
        }

                                        /*
        * @tc.name: hap_sign_test_001
        * @tc.desc: Generate a key pair and load it into the keystore.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(HapSignTest, hap_sign_test_027, testing::ext::TestSize.Level1)
        {
            SIGNATURE_TOOLS_LOGI("hello world !!!");
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            std::string signAlg = "SHA256w";
            std::string signCode = "0";
            std::string appCertFile = "./hapSign/app-release1.pem";
            std::string profileFile = "./hapSign/signed-profile.p7b";
            std::string inFile = "./hapSign/unsigned_with_cd_and_eocd.hap";
            std::string keystoreFile = "./hapSign/ohtest.p12";
            std::string outFile = "./hapSign/phone-default-signed.hap";
            char keyPwd[]  = "123456";
            char keystorePwd[] = "123456";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["signAlg"] = signAlg;
            (*params)["signCode"] = signCode;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["outFile"] = outFile;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = api->SignHap(params.get());
            EXPECT_EQ(ret, false);
        }


        /**
       * @tc.name: get_options_test_001
       * @tc.desc: Test function of GetOptions()  interface for SUCCESS.
       * @tc.type: FUNC
       * @tc.require: SR000H63TL
       */
        HWTEST_F(HapSignTest, get_options_test_001, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();
            std::string keyAlias = "oh-app1-key-v1";
            (*params)["keyAlias"] = keyAlias;
            SignerConfig signerConfig;
            signerConfig.SetOptions(params.get());
            EXPECT_EQ(params.get(), signerConfig.GetOptions());
        }


        /**
      * @tc.name: get_certificates_test_001
      * @tc.desc: Test function of GetCertificates()  interface for SUCCESS.
      * @tc.type: FUNC
      * @tc.require: SR000H63TL
      */
        HWTEST_F(HapSignTest, get_certificates_test_001, testing::ext::TestSize.Level1)
        {
            X509* newCert = X509_new();
            EXPECT_TRUE(X509_set_version(newCert, 2));
            SignerConfig signerConfig;
            signerConfig.SetX509CRLs(nullptr);
            signerConfig.GetX509CRLs();
            signerConfig.SetCertificates(nullptr);
            signerConfig.GetCertificates();
            signerConfig.GetSignParamMap();

            signerConfig.SetCertificates((STACK_OF(X509)*)newCert);
            EXPECT_EQ((STACK_OF(X509)*)newCert, signerConfig.GetCertificates());

            X509_free(newCert);
        }


        /**
      * @tc.name: get_X509_CRLs_test_001
      * @tc.desc: Test function of GetX509CRLs()  interface for SUCCESS.
      * @tc.type: FUNC
      * @tc.require: SR000H63TL
      */
        HWTEST_F(HapSignTest, get_X509_CRLs_test_001, testing::ext::TestSize.Level1)
        {
            STACK_OF(X509_CRL)* x509CRLs = nullptr;
            SignerConfig signerConfig;
            signerConfig.SetX509CRLs(x509CRLs);
            EXPECT_EQ(x509CRLs, signerConfig.GetX509CRLs());
        }


    /**
     * @tc.name: get_compatible_version_test_001
     * @tc.desc: Test function of GetCompatibleVersion()  interface for SUCCESS.
     * @tc.type: FUNC
     * @tc.require: SR000H63TL
     */
        HWTEST_F(HapSignTest, get_compatible_version_test_001, testing::ext::TestSize.Level1)
        {
            int n = 5;
            SignerConfig signerConfig;
            signerConfig.SetCompatibleVersion(n);
            EXPECT_EQ(5, signerConfig.GetCompatibleVersion());
        }

        /**
      * @tc.name: find_by_id_test_001
      * @tc.desc: Test function of FindById()  interface for SUCCESS.
      * @tc.type: FUNC
      * @tc.require: SR000H63TL
      */
        HWTEST_F(HapSignTest, find_by_id_test_001, testing::ext::TestSize.Level1)
        {
            const SignatureAlgorithmClass* tmp =
            SignatureAlgorithmClass::FindById(SignatureAlgorithmId::ECDSA_WITH_SHA256);
            EXPECT_EQ(&(SignatureAlgorithmClass::ECDSA_WITH_SHA256_INSTANCE), tmp);

            const SignatureAlgorithmClass* tmp1 =
            SignatureAlgorithmClass::FindById(SignatureAlgorithmId::ECDSA_WITH_SHA384);
            EXPECT_EQ(&(SignatureAlgorithmClass::ECDSA_WITH_SHA384_INSTANCE), tmp1);
        }
    }
}