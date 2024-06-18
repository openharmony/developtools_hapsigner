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
#include <openssl/ssl.h>
#include <gtest/gtest.h>
#include "signature_tools_log.h"
#include "options.h"
#include "sign_tool_service_impl.h"
#include "cert_tools.h"
#include "params_run_tool.h"
#include "localization_adapter.h"
#include "fs_digest_utils.h"
#include "constant.h"
#include <cstdio>
#include <cstring>

using namespace testing::ext;
using namespace OHOS::SignatureTools;

class GenerateCaTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void GenerateCaTest::SetUpTestCase(void)
{
    // input testsuit setup step，setup invoked before all testcases
}

void GenerateCaTest::TearDownTestCase(void)
{
    // input testsuit teardown step，teardown invoked after all testcases
}

void GenerateCaTest::SetUp(void)
{
    // input testcase setup step，setup invoked before each testcases
}

void GenerateCaTest::TearDown(void)
{
    // input testcase teardown step，teardown invoked after each testcases
}

// rootCa
/**
 * @tc.name: generate_ca_test_001
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    int basicConstraintsPathLen = 0;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/profile.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    int validity = 3650;
    char secret[] = "adhjkljasjhdk";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerkeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;
    (*params)["validity"] = validity;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, true);
}

// rootCa
/**
 * @tc.name: generate_ca_test_002
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    int basicConstraintsPathLen = 0;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/root-ca-test.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerkeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;
    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, true);
}

// rootCa
/**
 * @tc.name: generate_ca_test_003
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_003, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/root-ca-test.cer";
    int keySize = 384;
    int validity = 365;
    int basicConstraintsPathLen = 0;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["validity"] = validity;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_ca_test_004
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_004, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/root-ca-test.cer";
    int keySize = 384;
    int validity = 365;
    int basicConstraintsPathLen = 0;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["validity"] = validity;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_ca_test_005
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_005, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/root-ca-test.cer";
    int keySize = 384;
    int validity = 365;
    int basicConstraintsPathLen = 0;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keySize"] = keySize;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["validity"] = validity;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_ca_test_006
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_006, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    int basicConstraintsPathLen = 0;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/profile.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    char secret[] = "adhjkljasjhdk";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerkeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_ca_test_007
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_007, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    int basicConstraintsPathLen = 0;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/profile.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    char secret[] = "adhjkljasjhdk";
    char ksPwd[] = "123456";
    char isksPwd[] = "554245";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerkeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_ca_test_008
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_008, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    int basicConstraintsPathLen = 0;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/profile.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.pp12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    char secret[] = "adhjkljasjhdk";
    char ksPwd[] = "123456";
    char isksPwd[] = "554245";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerkeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_ca_test_009
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_009, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    int basicConstraintsPathLen = 5;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/profile.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    char secret[] = "adhjkljasjhdk";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerkeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_ca_test_010
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_010, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    int basicConstraintsPathLen = 5;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/root-ca-test.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerkeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;
    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_ca_test_011
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_011, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/root-ca-test.cer";
    int keySize = 384;
    int validity = 365;
    int basicConstraintsPathLen = 5;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["validity"] = validity;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_ca_test_012
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_012, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/root-ca-test.cer";
    int keySize = 384;
    int validity = 365;
    int basicConstraintsPathLen = 5;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["validity"] = validity;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_ca_test_013
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_013, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/root-ca-test.cer";
    int keySize = 384;
    int validity = 365;
    int basicConstraintsPathLen = 5;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keySize"] = keySize;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["validity"] = validity;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_ca_test_014
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_014, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    int basicConstraintsPathLen = 5;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/profile.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    char secret[] = "adhjkljasjhdk";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerkeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_ca_test_015
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_015, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-root-ca-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";
    std::string signAlg = "SHA384withECDSA";
    int basicConstraintsPathLen = 0;
    std::string keyStoreFile = "/data/test/generateCA/OpenHarmony.p12";
    std::string outFile = "/data/test/generateCA/root-ca1.cer";
    int validity = 365;
    int keySize = 384;
    char keypwd[] = "123456";
    char ksPwd[] = "123456";
    (*params)["keyPwd"] = keypwd;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;
    (*params)["validity"] = validity;
    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_ca_test_016
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_016, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app-sign-srv-ca-key-v1";
    std::string issuerkeyAlias = "oh-root-ca-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Application Signature Service CA";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";
    std::string signAlg = "SHA384withECDSA";
    int basicConstraintsPathLen = 0;
    std::string keyStoreFile = "/data/test/generateCA/OpenHarmony.p12";
    std::string outFile = "/data/test/generateCA/app-sign-srv-ca1.cer";
    int validity = 365;
    int keySize = 384;
    char keypwd[] = "123456";
    char ksPwd[] = "123456";
    char issuerPwd[] = "123456";
    (*params)["keyPwd"] = keypwd;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerKeyPwd"] = issuerPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;
    (*params)["validity"] = validity;
    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_ca_test_017
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_ca_test_017, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-profile-sign-srv-ca-key-v1";
    std::string issuerkeyAlias = "oh-root-ca-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Application Signature Service CA";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";
    std::string signAlg = "SHA384withECDSA";
    int basicConstraintsPathLen = 0;
    std::string keyStoreFile = "/data/test/generateCA/OpenHarmony.p12";
    std::string outFile = "/data/test/generateCA/profile-sign-srv-ca1.cer";
    int validity = 365;
    int keySize = 384;
    char keypwd[] = "123456";
    char ksPwd[] = "123456";
    char issuerPwd[] = "123456";
    (*params)["keyPwd"] = keypwd;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerKeyPwd"] = issuerPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;
    (*params)["validity"] = validity;
    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, true);
}


/**
 * @tc.name: generate_sub_cert_test_001
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_test_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char isksPwd[] = "123456";
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keyStoreFile"] = keystoreFile;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateSubCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_sub_cert_test_002
 * @tc.desc: Test function of GenerateCa()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_test_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    int basicConstraintsPathLen = 0;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/subca.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerKeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = EVP_PKEY_new();
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = X509_REQ_new();
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateSubCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, false);
}


/**
 * @tc.name: generate_sub_cert_test_003
 * @tc.desc: Test function of GenerateCa()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_test_003, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "";
    int basicConstraintsPathLen = 0;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/subca.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerKeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = EVP_PKEY_new();
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = X509_REQ_new();
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateSubCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_sub_cert_test_004
 * @tc.desc: Test function of GenerateCa()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_test_004, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    int basicConstraintsPathLen = 5;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/subca.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerKeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = EVP_PKEY_new();
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = X509_REQ_new();
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateSubCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_sub_cert_test_005
 * @tc.desc: Test function of GenerateCa()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_test_005, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "";
    int basicConstraintsPathLen = 5;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/subca.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerKeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = EVP_PKEY_new();
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = X509_REQ_new();
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateSubCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_sub_cert_test_006
 * @tc.desc: Test function of GenerateCa()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_test_006, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    int basicConstraintsPathLen = 0;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/subca.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keySize = 384;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    int validity = 365;
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerKeyStoreFile"] = issuerkeystroefile;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;
    (*params)["validity"] = validity;
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = EVP_PKEY_new();
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = X509_REQ_new();
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateSubCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, false);
}


/**
 * @tc.name: valid_file_type_test_001
 * @tc.desc: Test function of ValidFileType() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, valid_file_type_test_001, testing::ext::TestSize.Level1)
{
    std::string issuerkeystroefile = "ab.p12";
    bool ret = FileUtils::ValidFileType(issuerkeystroefile, { "p12", "jks" });
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: get_chars_test_001
 * @tc.desc: Test function of Options::GetChars() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, get_chars_test_001, testing::ext::TestSize.Level1)
{
    Options option;
    const std::string test = "test";
    char value[6] = "value";
    option[test] = value;
    char* tmp = option.GetChars(test);
    EXPECT_EQ(std::strcmp("value", tmp), 0);
}

/**
 * @tc.name: get_string_test_001
 * @tc.desc: Test function of Options::GetString() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, get_string_test_001, testing::ext::TestSize.Level1)
{
    Options option;
    std::string test = "test";
    std::string value = "value";
    option[test] = value;
    std::string str = option.GetString(test);
    EXPECT_EQ(std::strcmp("value", str.c_str()), 0);
}

/**
 * @tc.name: equals_test_001
 * @tc.desc: Test function of Options::Equals() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, equals_test_001, testing::ext::TestSize.Level1)
{
    Options option;
    const std::string test1 = "test1";
    const std::string test2 = "test2";
    bool ret = option.Equals(test1, test2);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: is_empty_test_001
 * @tc.desc: Test function of Options::IsEmpty() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, is_empty_test_001, testing::ext::TestSize.Level1)
{
    Options option;
    std::string test1 = "test1";
    bool ret = option.IsEmpty(test1);
    EXPECT_EQ(ret, false);
}

// general cert
/**
 * @tc.name: generate_cert_test_001
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char isksPwd[] = "123456";
    char keystorePwd[] = "123456";
    char issuerkeypwd[] = "123456";
    int validity = 365;
    std::string outfile = "/data/test/generateCA/general.cer";
    (*params)["keyPwd"] = secret;
    (*params)["issuerKeystorePwd"] = isksPwd;
    (*params)["issuerKeyPwd"] = issuerkeypwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyStoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    (*params)["validity"] = validity;
    (*params)["outFile"] = outfile;
    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, true);
}

// general cert
/**
 * @tc.name: generate_cert_test_002
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char isksPwd[] = "123456";
    char keystorePwd[] = "123456";
    char issuerkeypwd[] = "123456";
    std::string outFile = "/data/test/generateCA/rootCa.cer";
    (*params)["keyPwd"] = secret;
    (*params)["issuerKeystorePwd"] = isksPwd;
    (*params)["issuerKeyPwd"] = issuerkeypwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    (*params)["outFile"] = outFile;
    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, true);
}


// general cert
/**
 * @tc.name: generate_cert_test_003
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_003, testing::ext::TestSize.Level1)
{
    SIGNATURE_TOOLS_LOGI(" welcome to  test space !!! ");
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string keyUsage = "digitalSignature";
    std::string outFile = "general.cer";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char keystorePwd[] = "123456";
    int keySize = 384;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerKeyAlias;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = keystorePwd;

    (*params)["outFile"] = outFile;
    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, false);
}

// general cert
/**
 * @tc.name: generate_cert_test_004
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_004, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    std::string signAlg = "";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char isksPwd[] = "123456";
    char keystorePwd[] = "123456";
    char issuerkeypwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["issuerKeystorePwd"] = isksPwd;
    (*params)["issuerKeyPwd"] = issuerkeypwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;

    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, false);
}

// general cert
/**
 * @tc.name: generate_cert_test_005
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_005, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    std::string signAlg = "";
    std::string subject = "";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char isksPwd[] = "123456";
    char keystorePwd[] = "123456";
    char issuerkeypwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["issuerKeystorePwd"] = isksPwd;
    (*params)["issuerKeyPwd"] = issuerkeypwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, false);
}
// general cert
/**
 * @tc.name: generate_cert_test_006
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_006, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string keyUsage = "digitalSignature";
    std::string outFile = "/datamsge/test/generateCA/general.cer";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char keystorePwd[] = "123456";
    int keySize = 384;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = keystorePwd;

    (*params)["outFile"] = outFile;
    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_cert_test_007
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_007, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string subject = "";
    std::string signAlg = "";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string keyUsage = "digitalSignature";
    std::string outFile = "general.cer";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char keystorePwd[] = "123456";
    int keySize = 384;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = keystorePwd;

    (*params)["outFile"] = outFile;
    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_cert_test_008
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_008, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string signAlg = "SHA256withRSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string keyUsage = "digitalSignature";
    std::string outFile = "general.cer";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char keystorePwd[] = "123456";
    int keySize = 384;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerKeyAlias;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = keystorePwd;

    (*params)["outFile"] = outFile;
    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_cert_test_009
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_009, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string keyUsage = "digitalSignature";
    std::string outFile = "/mjssngek/test/generateCA/general.cer";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char keystorePwd[] = "123456";
    int keySize = 384;
    (*params)["keySize"] = keySize;
    (*params)["subject"] = subject;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["outFile"] = outFile;
    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, true);
}

// general cert
/**
 * @tc.name: generate_cert_test_010
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_010, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerKeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_cert_test_011
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_011, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = false;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerKeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, true);
}


/**
 * @tc.name: generate_cert_test_012
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_012, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = false;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerKeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, true);
}


/**
 * @tc.name: generate_cert_test_013
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_013, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = true;
    bool basicConstraintsCritical = false;
    bool basicConstraintsCa = false;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerKeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_cert_test_014
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_014, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = false;
    bool basicConstraintsCritical = false;
    bool basicConstraintsCa = false;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_cert_test_015
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_015, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = false;
    bool basicConstraintsCritical = false;
    bool basicConstraintsCa = false;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    EVP_PKEY* keyPair = EVP_PKEY_new();
    EXPECT_EQ(keyPair, nullptr);
    X509_REQ* csr = X509_REQ_new();
    EXPECT_EQ(csr, nullptr);
    bool ret = CertTools::GenerateCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_cert_test_016
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_016, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = false;
    bool basicConstraintsCritical = false;
    bool basicConstraintsCa = false;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = X509_REQ_new();
    EXPECT_EQ(csr, nullptr);
    bool ret = CertTools::GenerateCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_cert_test_017
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_017, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    std::string issuerKeystoreFile = "/data/test/generateKeyPair/pp.p12";
    std::string signAlg = "";
    std::string subject = "";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char isksPwd[] = "123456";
    char keystorePwd[] = "123456";
    char issuerkeypwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["issuerKeyPwd"] = issuerkeypwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keyStoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    (*params)["issuerKeystoreFile"] = issuerKeystoreFile;

    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_cert_test_018
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_018, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string keyUsage = "digitalSignature";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char isksPwd[] = "123456";
    char keystorePwd[] = "123456";
    char issuerkeypwd[] = "123456";
    std::string outFile = "/datamt/test/generateCA/general-ca-test.cer";
    (*params)["keyPwd"] = secret;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["issuerKeyPwd"] = issuerkeypwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keyStoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    (*params)["outFile"] = outFile;
    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_cert_test_019
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_019, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerkeyAlias = "oh-app-sign-srv-ca-key-v1";
    std::string keystoreFile = "/data/test/generateCA/OpenHarmony.p12";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Application Signature Service CA";
    std::string keyUsage = "digitalSignature";
    char secret[] = "123456";
    char keystorePwd[] = "123456";
    int validity = 365;
    std::string outfile = "/data/test/generateCA/single-app1.cer";
    (*params)["keyPwd"] = secret;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyStoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["validity"] = validity;
    (*params)["outFile"] = outfile;
    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_cert_test_020
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_020, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerkeyAlias = "oh-app-sign-srv-ca-key-v1";
    std::string keystoreFile = "/data/test/generateCA/OpenHarmony.p12";
    std::string signAlg = "";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Application Signature Service CA";
    std::string keyUsage = "digitalSignature";
    char secret[] = "123456";
    char keystorePwd[] = "123456";
    int validity = 365;
    std::string outfile = "/data/test/generateCA/single-app1.cer";
    (*params)["keyPwd"] = secret;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyStoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["validity"] = validity;
    (*params)["outFile"] = outfile;
    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_cert_test_021
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_021, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerkeyAlias = "oh-app-sign-srv-ca-key-v1";
    std::string keystoreFile = "/data/test/generateCA/OpenHarmony.p12";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Application Signature Service CA";
    std::string keyUsage = "digitalSignature";
    char secret[] = "123456";
    char keystorePwd[] = "123456";
    int validity = 365;
    std::string outfile = "/data/test/generateCA/single-app1.cer";
    (*params)["keyPwd"] = secret;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyStoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["keyUsage"] = keyUsage;
    (*params)["validity"] = validity;
    (*params)["outFile"] = outfile;
    bool ret = api->GenerateCert(params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: get_int_test_001
 * @tc.desc: Test function of GetInt()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, get_int_test_001, testing::ext::TestSize.Level1)
{
    Options option;
    std::string str = "test";
    int tmp = option.GetInt(str);
    EXPECT_EQ(std::to_string(tmp).size(), 1U);
}

/**
 * @tc.name: generate_app_cert_test_001
 * @tc.desc: Test function of GenerateAppCert()  interface for certChain SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_001, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    std::string issuerKeyAlias = "oh-app-sign-srv-ca-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/OpenHarmony.p12";
    std::string rootCaCertFile = "/data/test/generateCA/root-ca1.cer";
    std::string subCaCertFile = "/data/test/generateCA/app-sign-srv-ca1.cer";
    std::string outFile = "/data/test/generateCA/app-release1.pem";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    int validity = 365;
    std::string outForm = "certChain";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::CA_CERT_FILE] = rootCaCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;
    params[Options::OUT_FORM] = outForm;
    params[Options::VALIDITY] = validity;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_app_cert_test_002
 * @tc.desc: Test function of GenerateAppCert()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_002, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    std::string issuerKeyAlias = "oh-app-sign-srv-ca-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/OpenHarmony.p12";
    std::string outFile = "/data/test/generateCA/app-release1.cer";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    int validity = 365;
    std::string outForm = "cert";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;
    params[Options::OUT_FORM] = outForm;
    params[Options::VALIDITY] = validity;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_app_cert_test_003
 * @tc.desc: Test function of GenerateAppCert()  interface for certChain SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_003, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    std::string issuerKeyAlias = "oh-app-sign-srv-ca-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/OpenHarmony.p12";
    std::string rootCaCertFile = "/data/test/generateCA/root-ca1.cer";
    std::string subCaCertFile = "/data/test/generateCA/app-sign-srv-ca1.cer";  
    char secret[] = "123456";
    char ksPwd[] = "123456";
    int validity = 365;
    std::string outForm = "certChain";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::CA_CERT_FILE] = rootCaCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FORM] = outForm;
    params[Options::VALIDITY] = validity;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_app_cert_test_004
 * @tc.desc: Test function of GenerateAppCert()  interface for certChain SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_004, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    std::string issuerKeyAlias = "oh-app-sign-srv-ca-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/OpenHarmony.p12";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    int validity = 365;
    std::string outForm = "cert";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FORM] = outForm;
    params[Options::VALIDITY] = validity;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_app_cert_test_005
 * @tc.desc: Test function of GenerateAppCert()  interface for certChain FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_005, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "123456";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/apptest.p12";
    std::string caCertFile = "/data/test/generateCA/root-ca1test.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1test.cer";
    std::string outFile = "/data/test/generateCA/test-profile-cert-v1.cer";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    char isskeypwd[] = "123456";
    std::string outForm = "certChain";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::CA_CERT_FILE] = caCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;
    params[Options::OUT_FORM] = outForm;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_app_cert_test_006
 * @tc.desc: Test function of GenerateAppCert()  interface for certChain FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_006, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "45679887";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/apptest.p12";
    std::string caCertFile = "/data/test/generateCA/root-ca1test.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1test.cer";
    std::string outFile = "/data/test/generateCA/test-profile-cert-v1.cer";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    char isskeypwd[] = "123456";
    std::string outForm = "certChain";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::CA_CERT_FILE] = caCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;
    params[Options::OUT_FORM] = outForm;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_app_cert_test_007
 * @tc.desc: Test function of GenerateAppCert()  interface for certChain FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_007, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string keyStoreFile = "/data/test/generateCA/apptest.p12";
    std::string caCertFile = "/data/test/generateCA/root-ca1test.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1test.cer";
    std::string outFile = "/data/test/generateCA/test-profile-cert-v1.cer";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    char isskeypwd[] = "123456";
    std::string outForm = "certChain";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::CA_CERT_FILE] = caCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;
    params[Options::OUT_FORM] = outForm;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_profile_cert_test_001
 * @tc.desc: Test function of GenerateProfileCert()  interface for certChain SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profilecert_test_001, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "oh-profile-sign-srv-ca-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/OpenHarmony.p12";
    std::string outFile = "/data/test/generateCA/profile1.cer";
    int validity = 365;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    std::string outForm = "cert";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;
    params[Options::OUT_FORM] = outForm;
    params[Options::VALIDITY] = validity;
    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_profile_cert_test_002
 * @tc.desc: Test function of GenerateProfileCert()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profilecert_test_002, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "oh-profile-sign-srv-ca-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string rootCaCertFile = "/data/test/generateCA/root-ca1.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1.cer";
    std::string keyStoreFile = "/data/test/generateCA/OpenHarmony.p12";
    std::string outFile = "/data/test/generateCA/profile-release1.pem";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    std::string outForm = "certChain";
    int validity = 365;
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::CA_CERT_FILE] = rootCaCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;
    params[Options::OUT_FORM] = outForm;
    params[Options::VALIDITY] = validity;
    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_profile_cert_test_003
 * @tc.desc: Test function of GenerateProfileCert()  interface for certChain SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profilecert_test_003, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "oh-profile-sign-srv-ca-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/OpenHarmony.p12";
    int validity = 365;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    std::string outForm = "cert";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FORM] = outForm;
    params[Options::VALIDITY] = validity;
    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_profile_cert_test_004
 * @tc.desc: Test function of GenerateProfileCert()  interface for certChain SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profilecert_test_004, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "oh-profile-sign-srv-ca-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string rootCaCertFile = "/data/test/generateCA/root-ca1.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1.cer";
    std::string keyStoreFile = "/data/test/generateCA/OpenHarmony.p12";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    std::string outForm = "certChain";
    int validity = 365;
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::CA_CERT_FILE] = rootCaCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FORM] = outForm;
    params[Options::VALIDITY] = validity;
    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_profile_cert_test_005
 * @tc.desc: Test function of GenerateProfileCert()  interface for certChain FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profilecert_test_005, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "123456";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string caCertFile = "/data/test/generateCA/root-ca1test.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1test.cer";
    std::string outFile = "/data/test/generateCA/test-profile-cert-v1.cer";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    char isskeypwd[] = "123456";
    std::string outForm = "certChain";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::CA_CERT_FILE] = caCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;
    params[Options::OUT_FORM] = outForm;
    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_profile_cert_test_006
 * @tc.desc: Test function of GenerateProfileCert()  interface for certChain FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profilecert_test_006, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "45679887";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string caCertFile = "/data/test/generateCA/root-ca1test.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1test.cer";
    std::string outFile = "/data/test/generateCA/test-profile-cert-v1.cer";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    char isskeypwd[] = "123456";
    std::string outForm = "certChain";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::CA_CERT_FILE] = caCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;
    params[Options::OUT_FORM] = outForm;
    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_profile_cert_test_007
 * @tc.desc: Test function of GenerateProfileCert()  interface for certChain FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profilecert_test_007, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string caCertFile = "/data/test/generateCA/root-ca1test.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1test.cer";
    std::string outFile = "/data/test/generateCA/test-profile-cert-v1.cer";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    char isskeypwd[] = "123456";
    std::string outForm = "certChain";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::CA_CERT_FILE] = caCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;
    params[Options::OUT_FORM] = outForm;
    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, false);
}


/**
 * @tc.name: judge_alg_type_test_001
 * @tc.desc: Test function of JudgeAlgType()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, judge_alg_type_test_001, testing::ext::TestSize.Level1)
{
    std::string str = "ECC";
    bool ret = CmdUtil::JudgeAlgType(str);
    EXPECT_EQ(ret, true);
}
/**
 * @tc.name: judge_size_test_001
 * @tc.desc: Test function of JudgeSize()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, judge_size_test_001, testing::ext::TestSize.Level1)
{
    int size = 255;
    bool ret = CmdUtil::JudgeSize(size);
    EXPECT_EQ(ret, false);
}



/**
 * @tc.name:generate_root_cert_001
 * @tc.desc: Test function of :GenerateRootCertificate()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_root_cert_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    char keyPwd[] = "123456";
    int keySize = 256;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char keystorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keyStoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["algorithm"] = algorithm;
    (*params)["signAlgorithm"] = signAlgorithm;
    (*params)["subject"] = subject;
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = keyStoreHelper->GenerateKeyPair(algorithm, keySize);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_NE(cert, nullptr);
}
/**
 * @tc.name:generate_root_cert_002
 * @tc.desc: Test function of :GenerateRootCertificate()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_root_cert_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    char keyPwd[] = "123456";
    int keySize = 256;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char keystorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string basicConstraintsPathLen = "5";
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keyStoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["algorithm"] = algorithm;
    (*params)["signAlgorithm"] = signAlgorithm;
    (*params)["subject"] = subject;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = keyStoreHelper->GenerateKeyPair(algorithm, keySize);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_NE(cert, nullptr);
}

/**
 * @tc.name:generate_root_cert_003
 * @tc.desc: Test function of :GenerateRootCertificate()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_root_cert_003, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    char keyPwd[] = "123456";
    int keySize = 256;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char keystorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keyStoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["algorithm"] = algorithm;
    (*params)["signAlgorithm"] = signAlgorithm;
    (*params)["subject"] = subject;
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = keyStoreHelper->GenerateKeyPair(algorithm, keySize);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_EQ(csr, nullptr);
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_EQ(cert, nullptr);
}
/**
 * @tc.name: generate_end_cert_test_001
 * @tc.desc: Test function of GenerateEndCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_end_cert_test_001, testing::ext::TestSize.Level1)
{
    const char appSigningCapability[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x0A, 0x01, 0x00 };
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    int keySize = 256;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char keystorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    int validity = 3650;
    params["keyAlias"] = keyAlias;
    params["keyPwd"] = keyPwd;
    params["keySize"] = keySize;
    params["keystoreFile"] = keyStoreFile;
    params["keystorePwd"] = keystorePwd;
    params["algorithm"] = algorithm;
    params["signAlgorithm"] = signAlgorithm;
    params["subject"] = subject;
    params["issuer"] = issuer;
    params["validity"] = validity;
    LocalizationAdapter adapter(&params);
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = keyStoreHelper->GenerateKeyPair(algorithm, keySize);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateEndCert(csr, keyPair, adapter, appSigningCapability,
                                            sizeof(appSigningCapability));
    EXPECT_NE(cert, nullptr);
}

/**
 * @tc.name: generate_end_cert_test_002
 * @tc.desc: Test function of GenerateEndCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_end_cert_test_002, testing::ext::TestSize.Level1)
{
    char appSigningCapability[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x0A, 0x01, 0x00 };
    Options params;
    char keyPwd[] = "123456";
    int keySize = 256;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char keystorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    params["keyPwd"] = keyPwd;
    params["keySize"] = keySize;
    params["keystoreFile"] = keyStoreFile;
    params["keystorePwd"] = keystorePwd;
    params["algorithm"] = algorithm;
    params["signAlgorithm"] = signAlgorithm;
    params["subject"] = subject;
    params["issuer"] = issuer;
    LocalizationAdapter adapter(&params);
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = keyStoreHelper->GenerateKeyPair(algorithm, keySize);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateEndCert(csr, keyPair, adapter, appSigningCapability,
                                            sizeof(appSigningCapability));
    EXPECT_NE(cert, nullptr);
}

/**
 * @tc.name: generate_end_cert_test_003
 * @tc.desc: Test function of GenerateEndCert()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_end_cert_test_003, testing::ext::TestSize.Level1)
{
    char appSigningCapability[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x0A, 0x01, 0x00 };
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string keyAlias = "alias";
    char keyPwd[] = "123456";
    int keySize = 256;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char keystorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keyStoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["algorithm"] = algorithm;
    (*params)["signAlgorithm"] = signAlgorithm;
    (*params)["subject"] = subject;
    LocalizationAdapter adapter(params.get());
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = keyStoreHelper->GenerateKeyPair(algorithm, keySize);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateEndCert(csr, keyPair, adapter, appSigningCapability,
                                            sizeof(appSigningCapability));
    EXPECT_EQ(cert, nullptr);
}

/**
 * @tc.name: is_out_form_chain_test_001
 * @tc.desc: Test function of IsOutFormChain()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, is_out_form_chain_test_001, testing::ext::TestSize.Level1)
{
    Options params;
    std::string outForm = "certChain";
    params[Options::OUT_FORM] = outForm;
    LocalizationAdapter adapter(&params);
    bool ret = adapter.IsOutFormChain();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: is_out_form_chain_test_002
 * @tc.desc: Test function of IsOutFormChain()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, is_out_form_chain_test_002, testing::ext::TestSize.Level1)
{
    Options params;
    std::string outForm = "cert";
    params[Options::OUT_FORM] = outForm;
    LocalizationAdapter adapter(&params);
    bool ret = adapter.IsOutFormChain();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: get_cert_fromfile_test_001
 * @tc.desc: Test function of GetCertsFromFile()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, get_cert_fromfile_test_001, testing::ext::TestSize.Level1)
{
    Options params;
    std::string path = "";
    LocalizationAdapter adapter(&params);
    auto ret = adapter.GetCertsFromFile(path, " ");
    EXPECT_FALSE(ret.size() <= 1);
}

/**
 * @tc.name: get_cert_fromfile_test_002
 * @tc.desc: Test function of GetCertsFromFile()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, get_cert_fromfile_test_002, testing::ext::TestSize.Level1)
{
    Options params;
    std::string path = "certs";
    LocalizationAdapter adapter(&params);
    auto ret = adapter.GetCertsFromFile(path, " ");
    EXPECT_FALSE(ret.size() <= 1);
}

/**
 * @tc.name: output_cert_test_001
 * @tc.desc: Test function of OutPutCert() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, output_cert_test_001, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    char appSigningCapability[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x0A, 0x01, 0x00 };
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    int keySize = 256;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char keystorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    int validity = 3650;
    params["keyAlias"] = keyAlias;
    params["keyPwd"] = keyPwd;
    params["keySize"] = keySize;
    params["keystoreFile"] = keyStoreFile;
    params["keystorePwd"] = keystorePwd;
    params["algorithm"] = algorithm;
    params["signAlgorithm"] = signAlgorithm;
    params["subject"] = subject;
    params["issuer"] = issuer;
    params["validity"] = validity;
    LocalizationAdapter adapter(&params);
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = keyStoreHelper->GenerateKeyPair(algorithm, keySize);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateEndCert(csr, keyPair, adapter, appSigningCapability,
                                            sizeof(appSigningCapability));
    EXPECT_NE(cert, nullptr);
    bool ret = api.OutPutCert(cert, "/data/test/generateCA/test.cer");
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: output_cert_test_002
 * @tc.desc: Test function of OutPutCert() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, output_cert_test_002, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    char appSigningCapability[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x0A, 0x01, 0x00 };
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    int keySize = 256;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char keystorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    int validity = 3650;
    params["keyAlias"] = keyAlias;
    params["keyPwd"] = keyPwd;
    params["keySize"] = keySize;
    params["keystoreFile"] = keyStoreFile;
    params["keystorePwd"] = keystorePwd;
    params["algorithm"] = algorithm;
    params["signAlgorithm"] = signAlgorithm;
    params["subject"] = subject;
    params["issuer"] = issuer;
    params["validity"] = validity;
    LocalizationAdapter adapter(&params);
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = keyStoreHelper->GenerateKeyPair(algorithm, keySize);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateEndCert(csr, keyPair, adapter, appSigningCapability,
                                            sizeof(appSigningCapability));
    EXPECT_NE(cert, nullptr);
    bool ret = api.OutPutCert(cert, "/datasgje/test/generateCA/test.cer ");
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: output_cert_chain_test_001
 * @tc.desc: Test function of OutPutCertChain()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, output_cert_chain_test_001, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    X509* cert1 = X509_new();
    X509* cert2 = X509_new();
    X509* cert3 = X509_new();
    std::string path = "/data/test/generateCA/test.pem";
    std::vector<X509*> certs;
    certs.push_back(cert1);
    certs.push_back(cert2);
    certs.push_back(cert3);
    bool ret = api.OutPutCertChain(certs, path);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: output_cert_chain_test_002
 * @tc.desc: Test function of OutPutCertChain()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, output_cert_chain_test_002, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    X509* cert1 = X509_new();
    X509* cert2 = X509_new();
    X509* cert3 = X509_new();
    std::string path = "";
    std::vector<X509*> certs;
    certs.push_back(cert1);
    certs.push_back(cert2);
    certs.push_back(cert3);
    bool ret = api.OutPutCertChain(certs, path);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: print_x509_test_001
 * @tc.desc: Test function of PrintX509CertFromMemory()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, print_x509_test_001, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    X509* cert1 = X509_new();
    bool ret = api.PrintX509CertFromMemory(cert1);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: read_x509_test_001
 * @tc.desc: Test function of ReadfileToX509()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, read_x509_test_001, testing::ext::TestSize.Level1)
{
    std::string path = "";
    X509* cert1 = CertTools::ReadfileToX509(path);
    EXPECT_EQ(cert1, nullptr);
}

/**
 * @tc.name: read_x509_test_002
 * @tc.desc: Test function of ReadfileToX509  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, read_x509_test_002, testing::ext::TestSize.Level1)
{
    std::string path = "/data/test/generateCA/root-ca1.cer";
    X509* cert1 = CertTools::ReadfileToX509(path);
    EXPECT_NE(cert1, nullptr);
}

/**
 * @tc.name: get_and_output_cert_test_001
 * @tc.desc: Test function of GetAndOutPutCert()  interface for certchain SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, get_and_output_cert_test_001, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string caCertFile = "/data/test/generateCA/root-ca1.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1.cer";
    std::string outForm = "certChain";
    params[Options::CA_CERT_FILE] = caCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;
    params[Options::OUT_FORM] = outForm;
    LocalizationAdapter adapter(&params);
    std::string path = "/data/test/generateCA/root-ca1.cer";
    X509* cert1 = CertTools::ReadfileToX509(path);
    EXPECT_NE(cert1, nullptr);
    bool result = api.GetAndOutPutCert(adapter, cert1);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: get_and_output_cert_test_002
 * @tc.desc: Test function of GetAndOutPutCert()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, get_and_output_cert_test_002, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string outForm = "cert";
    params[Options::OUT_FORM] = outForm;
    LocalizationAdapter adapter(&params);
    std::string path = "/data/test/generateCA/root-ca1.cer";
    X509* cert1 = CertTools::ReadfileToX509(path);
    EXPECT_NE(cert1, nullptr);
    bool result = api.GetAndOutPutCert(adapter, cert1);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: get_and_output_cert_test_003
 * @tc.desc: Test function of GetAndOutPutCert()  interface for certchain SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, get_and_output_cert_test_003, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string caCertFile = "/data/test/generateCA/root-ca1.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1.cer";   
    std::string outFile = "/data/test/generateCA/certChain";
    params[Options::CA_CERT_FILE] = caCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;
    params[Options::OUT_FORM] = outFile;
    LocalizationAdapter adapter(&params);
    std::string path = "/data/test/generateCA/root-ca1.cer";
    X509* cert1 = CertTools::ReadfileToX509(path);
    EXPECT_NE(cert1, nullptr);
    bool result = api.GetAndOutPutCert(adapter, cert1);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: hap_verify_test_001
 * @tc.desc: Test function of VerifyHapSigner()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, hap_verify_test_001, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string inFile = "/data/test/generateCA/phone1-default-signed.hap";
    std::string outCertChain = "/data/test/generateCA/hap-verify.cer";
    std::string outProfile = "/data/test/generateCA/hap-profile.p7b";
    params[Options::IN_FILE] = inFile;
    params[Options::OUT_CERT_CHAIN] = outCertChain;
    params[Options::OUT_PROFILE] = outProfile;
    bool result = api.VerifyHapSigner(&params);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: hap_verify_test_002
 * @tc.desc: Test function of VerifyHapSigner()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, hap_verify_test_002, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string inFile = "";
    std::string outCertChain = "/data/test/generateCA/hap-verify.cer";
    std::string outProfile = "/data/test/generateCA/hap-profile.p7b";
    params[Options::IN_FILE] = inFile;
    params[Options::OUT_CERT_CHAIN] = outCertChain;
    params[Options::OUT_PROFILE] = outProfile;
    bool result = api.VerifyHapSigner(&params);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: generate_key_pair_test_001
 * @tc.desc: Test function of GetIssureKeyByAlias()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_key_pair_test_001, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string issuerkeyStroeFile = "/data/test/generateCA/ohtest.p12";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    char isskeypwd[] = "123456";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_STORE_FILE] = issuerkeyStroeFile;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    LocalizationAdapter adapter(&params);
    adapter.SetIssuerKeyStoreFile(true);
    EVP_PKEY* issueKeyPair = adapter.GetIssureKeyByAlias();
    EXPECT_NE(issueKeyPair, nullptr);
}
/**
 * @tc.name: generate_key_pair_test_002
 * @tc.desc: Test function of GetIssureKeyByAlias()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_key_pair_test_002, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string issuerkeyStroeFile = "/data/test/generateCA/ohtest.p12";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    char isskeypwd[] = "123456";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_STORE_FILE] = issuerkeyStroeFile;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    LocalizationAdapter adapter(&params);
    adapter.SetIssuerKeyStoreFile(true);
    EVP_PKEY* issueKeyPair = nullptr;
    adapter.GetKeyPair(true, &issueKeyPair);
    EXPECT_NE(issueKeyPair, nullptr);
}
/**
 * @tc.name: generate_key_pair_test_003
 * @tc.desc: Test function of GenerateKeyPair()  interface for cert FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_key_pair_test_003, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string issuerKeyAlias = "oh";
    std::string issuerkeyStroeFile = "/data/test/generateCA/ohtest.p12";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    char isskeypwd[] = "123456";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_STORE_FILE] = issuerkeyStroeFile;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    LocalizationAdapter adapter(&params);
    adapter.SetIssuerKeyStoreFile(true);
    EVP_PKEY* issueKeyPair = adapter.GetIssureKeyByAlias();
    EXPECT_EQ(issueKeyPair, nullptr);
}
/**
 * @tc.name: generate_key_pair_test_004
 * @tc.desc: Test function of GenerateKeyPair()  interface for cert FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_key_pair_test_004, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string issuerKeyAlias = "";
    std::string issuerkeyStroeFile = "";
    char isskeypwd[] = { 0 };
    params[Options::ISSUER_KEY_STORE_FILE] = issuerkeyStroeFile;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    LocalizationAdapter adapter(&params);
    adapter.SetIssuerKeyStoreFile(true);
    EVP_PKEY* issueKeyPair = adapter.GetIssureKeyByAlias();
    EXPECT_EQ(issueKeyPair, nullptr);
}

/**
 * @tc.name: set_expandedInf_ext_one_test_001
 * @tc.desc: Test function of SetExpandedInfExtOne()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_one_test_001, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext1 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool keyUsageCritical = true;
    std::string keyUsage = "digitalSignature";
    (*params)["keyUsage"] = keyUsage;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    bool cert1 = CertTools::SetExpandedInfExtOne(cert, params.get(), critical, ext1);
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: set_expandedInf_ext_one_test_002
 * @tc.desc: Test function of SetExpandedInfExtOne()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_one_test_002, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext1 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool keyUsageCritical = false;
    std::string keyUsage = "digitalSignature";
    (*params)["keyUsage"] = keyUsage;
    (*params)["keyUsageCritical"] = keyUsageCritical;
    bool cert1 = CertTools::SetExpandedInfExtOne(cert, params.get(), critical, ext1);
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: set_expandedInf_ext_two_test_001
 * @tc.desc: Test function of SetExpandedInfExtTwo()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_two_test_001, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext2 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool extKeyUsageCritical = true;
    std::string extKeyUsage = "clientAuthentication";
    (*params)["extKeyUsageCritical"] = extKeyUsageCritical;
    (*params)["extKeyUsage"] = extKeyUsage;
    bool cert1 = CertTools::SetExpandedInfExtTwo(cert, params.get(), critical, ext2);
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: set_expandedInf_ext_two_test_002
 * @tc.desc: Test function of SetExpandedInfExtTwo()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_two_test_002, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext2 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool extKeyUsageCritical = false;
    std::string extKeyUsage = "clientAuthentication";
    (*params)["extKeyUsageCritical"] = extKeyUsageCritical;
    (*params)["extKeyUsage"] = extKeyUsage;
    bool cert1 = CertTools::SetExpandedInfExtTwo(cert, params.get(), critical, ext2);
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: set_expandedInf_ext_three_test_001
 * @tc.desc: Test function of SetExpandedInfExtThree()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_three_test_001, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext3 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    bool cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, false);
}


/**
 * @tc.name: set_expandedInf_ext_three_test_002
 * @tc.desc: Test function of SetExpandedInfExtThree()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_three_test_002, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext3 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool basicConstraints = true;
    bool basicConstraintsCritical = false;
    bool basicConstraintsCa = true;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    bool cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: set_expandedInf_ext_three_test_003
 * @tc.desc: Test function of SetExpandedInfExtThree()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_three_test_003, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext3 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = false;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    bool cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, false);
}


/**
 * @tc.name: set_expandedInf_ext_three_test_004
 * @tc.desc: Test function of SetExpandedInfExtThree()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_three_test_004, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext3 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool basicConstraints = false;
    bool basicConstraintsCritical = false;
    bool basicConstraintsCa = false;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    bool cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: set_expandedInf_ext_three_test_005
 * @tc.desc: Test function of SetExpandedInfExtThree()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_three_test_005, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext3 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool basicConstraints = true;
    bool basicConstraintsCa = true;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    (*params)["basicConstraints"] = basicConstraints;
    bool cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: set_expandedInf_ext_three_test_006
 * @tc.desc: Test function of SetExpandedInfExtThree()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_three_test_006, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext3 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool basicConstraints = true;
    bool basicConstraintsCa = false;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    bool cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: set_expandedInf_ext_three_test_007
 * @tc.desc: Test function of SetExpandedInfExtThree()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_three_test_007, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext3 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool basicConstraints = false;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    bool cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: set_expandedInf_ext_three_test_008
 * @tc.desc: Test function of SetExpandedInfExtThree()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_three_test_008, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext3 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool basicConstraints = false;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = false;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    bool cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: set_expandedInf_ext_three_test_009
 * @tc.desc: Test function of SetExpandedInfExtThree()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_expandedInf_ext_three_test_009, testing::ext::TestSize.Level1)
{
    X509_EXTENSION* ext3 = nullptr;
    std::string critical = "critical";
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    bool basicConstraints = false;
    bool basicConstraintsCritical = false;
    bool basicConstraintsCa = true;
    (*params)["basicConstraints"] = basicConstraints;
    (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
    (*params)["basicConstraintsCa"] = basicConstraintsCa;
    bool cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: generate_sub_cert_to_file_test_001
 * @tc.desc: Test function of GenerateCaToFile()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_to_file_test_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    std::string outFile = "/datamt/test/generateCA/sub-ca-test.cer";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlgorithm"] = signAlgorithm;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["outFile"] = outFile;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    bool ret = api->GenerateSubCertToFile(params.get(), keyPair);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_sub_cert_to_file_test_002
 * @tc.desc: Test function of GenerateCaToFile()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_to_file_test_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_NE(cert, nullptr);
    bool ret = api->GenerateSubCertToFile(params.get(), keyPair);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_sub_cert_to_file_test_003
 * @tc.desc: Test function of GenerateCaToFile()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_to_file_test_003, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_EQ(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_NE(cert, nullptr);
    bool ret = api->GenerateSubCertToFile(params.get(), keyPair);
    EXPECT_EQ(ret, true);
}
/**
 * @tc.name: generate_sub_cert_to_file_test_004
 * @tc.desc: Test function of GenerateSubCertToFile()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_to_file_test_004, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_NE(cert, nullptr);
    bool ret = api->GenerateSubCertToFile(params.get(), keyPair);
    EXPECT_EQ(ret, false);
}
/**
 * @tc.name: generate_sub_cert_to_file_test_005
 * @tc.desc: Test function of GenerateCaToFile()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_to_file_test_005, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECD";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_NE(cert, nullptr);
    bool ret = api->GenerateSubCertToFile(params.get(), keyPair);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_sub_cert_to_file_test_006
 * @tc.desc: Test function of GenerateCaToFile()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_to_file_test_006, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECD";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;   
    EVP_PKEY* keyPair = nullptr;
    bool ret = api->GenerateSubCertToFile(params.get(), keyPair);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: generate_sub_cert_to_file_test_007
 * @tc.desc: Test function of GenerateCaToFile()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_sub_cert_to_file_test_007, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECD";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    std::string outFile = "/datamt/test/generateCA/sub-ca-test.cer";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlgorithm"] = signAlgorithm;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["outFile"] = outFile;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    bool ret = api->GenerateSubCertToFile(params.get(), keyPair);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: set_cert_version_test_001
 * @tc.desc: Test function of SetCertVersion()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_cert_version_test_001, testing::ext::TestSize.Level1)
{
    X509* cert = nullptr;
    bool res = CertTools::SetCertVersion(cert, 1);
    EXPECT_EQ(res, false);
}
/**
 * @tc.name: set_pubkey_and_sign_cert_test_001
 * @tc.desc: Test function of SetPubkeyAndSignCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_pubkey_and_sign_cert_test_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlgorithm"] = signAlgorithm;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlgorithm, issuer);
    EXPECT_NE(issuercsr, nullptr);
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_NE(cert, nullptr);
    bool cert1 = CertTools::SetPubkeyAndSignCert(cert, issuercsr, csr, keyPair, params.get());
    EXPECT_NE(cert1, false);
}


/**
 * @tc.name: set_pubkey_and_sign_cert_test_002
 * @tc.desc: Test function of SetPubkeyAndSignCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_pubkey_and_sign_cert_test_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlgorithm"] = signAlgorithm;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlgorithm, issuer);
    EXPECT_NE(issuercsr, nullptr);
    X509* cert = nullptr;
    EXPECT_EQ(cert, nullptr);
    bool cert1 = CertTools::SetPubkeyAndSignCert(cert, issuercsr, csr, keyPair, params.get());
    EXPECT_NE(cert1, false);
}


/**
 * @tc.name: set_pubkey_and_sign_cert_test_003
 * @tc.desc: Test function of SetPubkeyAndSignCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_pubkey_and_sign_cert_test_003, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";   
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = X509_REQ_new();
    EXPECT_EQ(csr, nullptr);
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlg, issuer);
    EXPECT_NE(issuercsr, nullptr);
    X509* cert = nullptr;
    EXPECT_EQ(cert, nullptr);
    bool cert1 = CertTools::SetPubkeyAndSignCert(cert, issuercsr, csr, keyPair, params.get());
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: set_pubkey_and_sign_cert_test_004
 * @tc.desc: Test function of SetPubkeyAndSignCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_pubkey_and_sign_cert_test_004, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/key.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = X509_REQ_new();
    EXPECT_EQ(csr, nullptr);
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlg, issuer);
    EXPECT_NE(issuercsr, nullptr);
    X509* cert = nullptr;
    EXPECT_EQ(cert, nullptr);
    bool cert1 = CertTools::SetPubkeyAndSignCert(cert, issuercsr, csr, keyPair, params.get());
    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: set_pubkey_and_sign_cert_test_005
 * @tc.desc: Test function of SetPubkeyAndSignCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_pubkey_and_sign_cert_test_005, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/key.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = X509_REQ_new();
    EXPECT_EQ(csr, nullptr);
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlg, issuer);
    EXPECT_NE(issuercsr, nullptr);
    X509* cert = nullptr;
    EXPECT_EQ(cert, nullptr);
    bool cert1 = CertTools::SetPubkeyAndSignCert(cert, issuercsr, csr, keyPair, params.get());
    EXPECT_NE(cert1, false);
}



/**
 * @tc.name: set_cert_serial_test_003
 * @tc.desc: Test function of SetCertSubjectName()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_cert_serial_test_001, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    X509_REQ* req = X509_REQ_new();
    bool res = CertTools::SetCertSubjectName(cert, req);
    X509_REQ_free(req);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: set_cert_validity_test_001
 * @tc.desc: Test function of SetCertValidityStartAndEnd()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_cert_validity_test_001, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    bool res = CertTools::SetCertValidityStartAndEnd(cert, -1, 2);
    X509_free(cert);
    EXPECT_EQ(res, false);
}
/**
 * @tc.name: set_cert_validity_test_002
 * @tc.desc: Test function of SetCertValidityStartAndEnd()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_cert_validity_test_002, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    bool res = CertTools::SetCertValidityStartAndEnd(cert, 1, -2);
    X509_free(cert);
    EXPECT_EQ(res, false);
}


/**
 * @tc.name: X509_certverify_test_001
 * @tc.desc: Test function of X509CertVerify()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, X509_certverify_test_001, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    bool ret = api->X509CertVerify(cert, keyPair);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: X509_certverify_test_002
 * @tc.desc: Test function of X509CertVerify()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */

HWTEST_F(GenerateCaTest, X509_certverify_test_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    EVP_PKEY* keyPair = EVP_PKEY_new();
    bool ret = api->X509CertVerify(cert, keyPair);
    EXPECT_NE(ret, false);
}


/**
 * @tc.name: X509_certverify_test_003
 * @tc.desc: Test function of X509CertVerify()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, X509_certverify_test_003, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509* cert = X509_new();
    bool ret = api->X509CertVerify(cert, keyPair);
    X509_free(cert);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: isempty_test_001
 * @tc.desc: Test function of IsEmpty()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, isempty_test_001, testing::ext::TestSize.Level1)
{
    std::string cs = "";
    bool res = FileUtils::IsEmpty(cs);
    EXPECT_EQ(res, true);
}
/**
 * @tc.name: Read_File_By_Offset_And_Length_test_001
 * @tc.desc: Test function of ReadInputByOffsetAndLength()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, Read_File_By_Offset_And_Length_test_001, testing::ext::TestSize.Level1)
{
    std::ifstream file("/data/test/generateKeyPair/keypair.p12");
    std::string ret("std::string& ret");
    int res = FileUtils::ReadFileByOffsetAndLength(file, 1, 50, ret);
    EXPECT_EQ(res, 0);
}
/**
 * @tc.name: Read_File_By_Offset_And_Length_test_002
 * @tc.desc: Test function of ReadInputByOffsetAndLength()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, Read_Input_By_Offset_And_Length_test_002, testing::ext::TestSize.Level1)
{
    std::ifstream file("/data/test/");
    std::string ret("std::string& ret");
    int res = FileUtils::ReadInputByOffsetAndLength(file, 111, 2147483647, ret);
    EXPECT_EQ(res, -1);
}
/**
* @tc.name: Read_File_By_Length_test_001
* @tc.desc: Test function of AppendWriteFileByOffsetToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Read_Input_By_Length_test_001, testing::ext::TestSize.Level1)
{
    std::ifstream file("/data/test/");
    std::string ret("std::string& ret");
    int res = FileUtils::ReadInputByLength(file, 2147483647, ret);
    EXPECT_EQ(res, -1);
}
/**
* @tc.name: Append_Write_File_ByOffset_To_File_test_001
* @tc.desc: Test function of AppendWriteFileByOffsetToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Append_Write_File_ByOffset_To_File_test_001, testing::ext::TestSize.Level1)
{
    std::ifstream file("");
    std::ofstream out("");
    bool res = FileUtils::AppendWriteFileByOffsetToFile(file, out, 10000, 100000);
    EXPECT_EQ(res, false);
}
/**
* @tc.name: Append_Write_File_ByOffset_To_File_test_002
* @tc.desc: Test function of AppendWriteFileByOffsetToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Append_Write_File_ByOffset_To_File_test_002, testing::ext::TestSize.Level1)
{
    std::ifstream file("/data/test/generateKeyPair/keypair.p12");
    std::ofstream out("/data/test/generateKeyPair/test.txt");
    bool res = FileUtils::AppendWriteFileByOffsetToFile(file, out, 10, 100);
    EXPECT_EQ(res, false);
}
/**
* @tc.name: Append_Write_File_ByOffset_To_File_test_003
* @tc.desc: Test function of AppendWriteFileByOffsetToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Append_Write_File_ByOffset_To_File_test_003, testing::ext::TestSize.Level1)
{
    std::ifstream file("/data/test/generateKeyPair/keypair.p12");
    std::ofstream out("");
    bool res = FileUtils::AppendWriteFileByOffsetToFile(file, out, 10, 100);
    EXPECT_EQ(res, false);
}
/**
* @tc.name: Is_Runnable_File_test_001
* @tc.desc: Test function of IsRunnableFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Is_Runnable_File_test_001, testing::ext::TestSize.Level1)
{
    std::string name = "";
    bool res = FileUtils::IsRunnableFile(name);
    EXPECT_EQ(res, false);
}
/**
* @tc.name: WriteByteToOutFile_test_001
* @tc.desc: Test function of WriteByteToOutFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, WriteByteToOutFile_test_001, testing::ext::TestSize.Level1)
{
    std::string bytes = "587469";
    std::ofstream outFile("/data/test/test.txt");
    bool res = FileUtils::WriteByteToOutFile(bytes, outFile);
    EXPECT_EQ(res, true);
}
/**
* @tc.name: WriteByteToOutFile_test_002
* @tc.desc: Test function of WriteByteToOutFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, WriteByteToOutFile_test_002, testing::ext::TestSize.Level1)
{
    std::string bytes = "";
    std::ofstream outFile("");
    bool res = FileUtils::WriteByteToOutFile(bytes, outFile);
    EXPECT_EQ(res, false);
}
/**
* @tc.name: ReadFile_test_002
* @tc.desc: Test function of ReadFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, ReadFile_test_002, testing::ext::TestSize.Level1)
{
    std::string path = "/data/test/";
    std::string ret;
    int res = FileUtils::ReadFile(path, ret);
    EXPECT_EQ(res, -104);
}
/**
* @tc.name: WriteByteToOutFile_test_003
* @tc.desc: Test function of WriteByteToOutFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, WriteByteToOutFile_test_003, testing::ext::TestSize.Level1)
{
    std::string bytes = "111";
    std::string outFile = "/data/test/test.txt";
    bool res = FileUtils::WriteByteToOutFile(bytes, outFile);
    EXPECT_EQ(res, true);
}
/**
* @tc.name: WriteByteToOutFile_test_004
* @tc.desc: Test function of WriteByteToOutFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, WriteByteToOutFile_test_004, testing::ext::TestSize.Level1)
{
    std::string bytes = "111";
    std::string outFile = "";
    int res = FileUtils::WriteByteToOutFile(bytes, outFile);
    EXPECT_EQ(res, false);
}
/**
* @tc.name: ParsePkcs7Package_test_001
* @tc.desc: Test function of ParsePkcs7Package()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, ParsePkcs7Package_test_001, testing::ext::TestSize.Level1)
{
    const unsigned char packageData[] = { 0 };
    Pkcs7Context pkcs7Context;
    bool res = VerifyHapOpensslUtils::ParsePkcs7Package(packageData, 10, pkcs7Context);
    EXPECT_EQ(res, false);
}
/**
* @tc.name: ParsePkcs7Package_test_002
* @tc.desc: Test function of ParsePkcs7Package()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, ParsePkcs7Package_test_002, testing::ext::TestSize.Level1)
{
    const unsigned char packageData[] = { 1, 1, 1, 1, 1 };
    Pkcs7Context pkcs7Context;
    bool res = VerifyHapOpensslUtils::ParsePkcs7Package(packageData, 10, pkcs7Context);
    EXPECT_EQ(res, false);
}
/**
* @tc.name: GetCertChains_test_001
* @tc.desc: Test function of GetCertChains()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, GetCertChains_test_001, testing::ext::TestSize.Level1)
{
    PKCS7* p7 = nullptr;
    Pkcs7Context pkcs7Context;
    bool ret = VerifyHapOpensslUtils::GetCertChains(p7, pkcs7Context);
    EXPECT_EQ(ret, false);
}
/**
* @tc.name: GetCertChains_test_002
* @tc.desc: Test function of GetCertChains()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, GetCertChains_test_002, testing::ext::TestSize.Level1)
{
    PKCS7* p7 = PKCS7_new();
    Pkcs7Context pkcs7Context;
    bool ret = VerifyHapOpensslUtils::GetCertChains(p7, pkcs7Context);
    PKCS7_free(p7);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: set_bisic_constraints_patchlen_test_001
 * @tc.desc: Test function of SetBisicConstraintsPatchLen()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */

HWTEST_F(GenerateCaTest, set_bisic_constraints_patchlen_test_001, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    Options options;
    options[Options::BASIC_CONSTRAINTS_PATH_LEN] = 1;
    bool cert1 = CertTools::SetBisicConstraintsPatchLen(&options, cert);
    EXPECT_NE(cert1, false);
}


/**
 * @tc.name: sign_for_subcert_test_001
 * @tc.desc: Test function of SignForSubCert()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, sign_for_subcert_test_001, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlg, issuer);
    bool cert1 = CertTools::SignForSubCert(cert, csr, issuercsr, keyPair, params.get());

    EXPECT_EQ(cert1, false);
}


/**
 * @tc.name: sign_for_subcert_test_002
 * @tc.desc: Test function of SignForSubCert()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, sign_for_subcert_test_002, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = X509_REQ_new();
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlg, issuer);
    bool cert1 = CertTools::SignForSubCert(cert, csr, issuercsr, keyPair, params.get());
    EXPECT_EQ(cert1, false);
}


/**
 * @tc.name: sign_for_subcert_test_003
 * @tc.desc: Test function of SignForSubCert()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, sign_for_subcert_test_003, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    X509_REQ* issuercsr = X509_REQ_new();
    bool cert1 = CertTools::SignForSubCert(cert, csr, issuercsr, keyPair, params.get());

    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: sign_for_subcert_test_004
 * @tc.desc: Test function of SignForSubCert()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, sign_for_subcert_test_004, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA256withECDSA";
    std::string subject = "";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlg, issuer);
    bool cert1 = CertTools::SignForSubCert(cert, csr, issuercsr, keyPair, params.get());

    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: sign_for_subcert_test_005
 * @tc.desc: Test function of SignForSubCert()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, sign_for_subcert_test_005, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA256withRSA";
    std::string subject = "";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlg, issuer);
    bool cert1 = CertTools::SignForSubCert(cert, csr, issuercsr, keyPair, params.get());

    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: sign_for_subcert_test_006
 * @tc.desc: Test function of SignForSubCert()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, sign_for_subcert_test_006, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA256withECDSA";
    std::string issuer = "";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = EVP_PKEY_new();
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlg, issuer);
    bool cert1 = CertTools::SignForSubCert(cert, csr, issuercsr, keyPair, params.get());

    EXPECT_NE(cert1, false);
}

/**
 * @tc.name: get_csr_test_001
 * @tc.desc: Test function of GetCsr()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */

HWTEST_F(GenerateCaTest, get_csr_test_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string signAlg = "";
    std::string subject = "";
    EVP_PKEY* keyPair = nullptr;
    bool ret = api->GetCsr(keyPair, signAlg, subject);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: get_csr_test_002
 * @tc.desc: Test function of GetCsr()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, get_csr_test_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    EVP_PKEY* keyPair = nullptr;
    bool ret = api->GetCsr(keyPair, signAlg, subject);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: save_cert_to_file_test_001
 * @tc.desc: Test function of CertTools::SaveCertTofile interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, save_cert_to_file_test_001, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    EXPECT_NE(cert, nullptr);
    std::string rootoutFile = "root-ca1.cer";
    CertTools::SaveCertTofile(rootoutFile, cert);
}


/**
 * @tc.name: save_cert_to_file_test_002
 * @tc.desc: Test function of CertTools::SaveCertTofile()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, save_cert_to_file_test_002, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    std::string rootoutFile = "";
    CertTools::SaveCertTofile(rootoutFile, cert);
}

/**
 * @tc.name: isempty_test_002
 * @tc.desc: Test function of IsEmpty()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, isempty_test_002, testing::ext::TestSize.Level1)
{
    std::string cs = "1234";
    bool res = FileUtils::IsEmpty(cs);
    EXPECT_EQ(res, false);
}
/**
 * @tc.name: write_test_001
 * @tc.desc: Test function of IsEmpty()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, write_test_001, testing::ext::TestSize.Level1)
{
    std::string cs = "1234";
    int res = FileUtils::Write(cs, "/data/test/");
    EXPECT_EQ(res, -103);
}
/**
 * @tc.name: read_test_001
 * @tc.desc: Test function of IsEmpty()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, read_test_001, testing::ext::TestSize.Level1)
{
    std::string cs = "1234";
    std::ifstream input;

    int res = FileUtils::Read(input, cs);
    EXPECT_EQ(res, -104);
}
/**
* @tc.name: Append_Write_File_ByOffset_To_File_test_004
* @tc.desc: Test function of AppendWriteFileByOffsetToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Append_Write_File_ByOffset_To_File_test_004, testing::ext::TestSize.Level1)
{
    std::string file = "/data/test/";
    std::ifstream in(file);
    std::ofstream out("");
    bool res = FileUtils::AppendWriteFileByOffsetToFile(in, out, 10, 100);
    EXPECT_EQ(res, false);
    out.close();
    in.close();
}
/**
* @tc.name: Append_Write_File_ByOffset_To_File_test_005
* @tc.desc: Test function of AppendWriteFileByOffsetToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Append_Write_File_ByOffset_To_File_test_005, testing::ext::TestSize.Level1)
{
    std::string file = "/data/test/generateKeyPair/keypair.p12";
    std::ifstream in(file);
    std::ofstream out("/data/test/generateKeyPair/test.txt");
    bool res = FileUtils::AppendWriteFileByOffsetToFile(in, out, 10, 100);
    EXPECT_EQ(res, false);
    out.close();
    in.close();
}
/**
* @tc.name: Append_Write_File_ByOffset_To_File_test_006
* @tc.desc: Test function of AppendWriteFileByOffsetToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Append_Write_File_ByOffset_To_File_test_006, testing::ext::TestSize.Level1)
{
    std::string file = "/data/test/";
    std::ifstream in(file);
    std::ofstream out("/data/test/generateKeyPair/test.txt");
    bool res = FileUtils::AppendWriteFileByOffsetToFile(in, out, 10, 100);
    EXPECT_EQ(res, false);
    out.close();
    in.close();
}

/**
* @tc.name: Verify_Hap_test_001
* @tc.desc: Test function of VerifyHapSigner()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Verify_Hap_test_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string inForm = "zip";
    (*params)["inForm"] = inForm;
    bool res = api->VerifyHapSigner(params.get());
    EXPECT_EQ(res, true);
}

/**
* @tc.name: Verify_Hap_test_002
* @tc.desc: Test function of VerifyHapSigner()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Verify_Hap_test_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string inForm = "elf";
    (*params)["inForm"] = inForm;
    bool res = api->VerifyHapSigner(params.get());
    EXPECT_EQ(res, false);
}

/**
* @tc.name: Verify_Hap_test_003
* @tc.desc: Test function of VerifyHapSigner()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Verify_Hap_test_003, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string inForm = "bin";
    (*params)["inForm"] = inForm;
    bool res = api->VerifyHapSigner(params.get());
    EXPECT_EQ(res, true);
}

/**
* @tc.name: Verify_Hap_test_004
* @tc.desc: Test function of VerifyHapSigner()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Verify_Hap_test_004, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string inForm = "mmmmm";
    (*params)["inForm"] = inForm;
    bool res = api->VerifyHapSigner(params.get());
    EXPECT_EQ(res, false);
}

/**
* @tc.name: generate_root_cert_to_flie_001
* @tc.desc: Test function of GenerateRootCertToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, generate_root_cert_to_flie_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    EVP_PKEY* keyPair = nullptr;
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    bool res = api->GenerateRootCertToFile(params.get(), keyPair);
    EXPECT_EQ(res, false);
}

/**
* @tc.name: generate_root_cert_to_flie_002
* @tc.desc: Test function of GenerateRootCertToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, generate_root_cert_to_flie_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char isksPwd[] = "123456";
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keyStoreFile"] = keystoreFile;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    bool res = api->GenerateRootCertToFile(params.get(), keyPair);
    EXPECT_EQ(res, false);
}


/**
* @tc.name: generate_root_cert_to_flie_003
* @tc.desc: Test function of GenerateRootCertToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, generate_root_cert_to_flie_003, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA256withRSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char isksPwd[] = "123456";
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keyStoreFile"] = keystoreFile;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    bool res = api->GenerateRootCertToFile(params.get(), keyPair);
    EXPECT_EQ(res, false);
}

/**
* @tc.name: generate_root_cert_to_flie_004
* @tc.desc: Test function of GenerateRootCertToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, generate_root_cert_to_flie_004, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateKeyPair/keypair.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    char isksPwd[] = "123456";
    std::string outFile = "/datamt/test/generateCA/root-ca-test.cer";
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keyStoreFile"] = keystoreFile;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["outFile"] = outFile;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    bool res = api->GenerateRootCertToFile(params.get(), keyPair);
    EXPECT_EQ(res, false);
}

/**
* @tc.name: out_put_mode_of_cert_001
* @tc.desc: Test function of OutputModeOfCert()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, out_put_mode_of_cert_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    X509* cert = X509_new();
    std::string outFile = "/datamt/test/generateCA/sub-ca-test.cer";
    (*params)["outFile"] = outFile;
    bool res = api->OutputModeOfCert(cert, params.get());
    EXPECT_EQ(res, false);
}

/**
* @tc.name: generate_key_store_001
* @tc.desc: Test function of GenerateKeyStore()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, generate_key_store_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "";
    (*params)["keyAlias"] = keyAlias;
    bool res = api->GenerateKeyStore(params.get());
    EXPECT_EQ(res, false);
}

/**
* @tc.name: handle_issuer_key_alias_empty_001
* @tc.desc: Test function of HandleIssuerKeyAliasEmpty()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, handle_issuer_key_alias_empty_001, testing::ext::TestSize.Level1)
{
    std::unique_ptr<FileUtils> sutils = std::make_unique<FileUtils>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keystoreFile = "/data/test/generateCA/other.p12";
    std::string issuerKeystoreFile = "/data/test/generateCA/issuer.p12";
    (*params)["issuerKeystoreFile"] = issuerKeystoreFile;
    (*params)["keystoreFile"] = keystoreFile;
    api->HandleIssuerKeyAliasEmpty(params.get());
}

/**
* @tc.name: handle_issuer_key_alias_empty_002
* @tc.desc: Test function of HandleIssuerKeyAliasEmpty()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, handle_issuer_key_alias_empty_002, testing::ext::TestSize.Level1)
{
    std::unique_ptr<FileUtils> sutils = std::make_unique<FileUtils>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    char keystorepwd[] = "";
    char issuerstorepwd[] = "123456";
    std::string keystoreFile = "/data/test/generateCA/other.p12";
    std::string issuerKeystoreFile = "/data/test/generateCA/other.p12";
    (*params)["issuerKeystoreFile"] = issuerKeystoreFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["issuerKeystorePwd"] = issuerstorepwd;
    (*params)["keystorePwd"] = keystorepwd;
    api->HandleIssuerKeyAliasEmpty(params.get());
}

/**
* @tc.name: handle_issuer_key_alias_empty_003
* @tc.desc: Test function of HandleIssuerKeyAliasEmpty()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, handle_issuer_key_alias_empty_003, testing::ext::TestSize.Level1)
{
    std::unique_ptr<FileUtils> sutils = std::make_unique<FileUtils>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    char keystorepwd[] = "234567";
    char issuerstorepwd[] = "123456";
    std::string keystoreFile = "/data/test/generateCA/other.p12";
    std::string issuerKeystoreFile = "/data/test/generateCA/other.p12";
    (*params)["issuerKeystoreFile"] = issuerKeystoreFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["issuerKeystorePwd"] = issuerstorepwd;
    (*params)["keystorePwd"] = keystorepwd;
    api->HandleIssuerKeyAliasEmpty(params.get());
}

/**
* @tc.name: handle_issuer_key_alias_empty_004
* @tc.desc: Test function of HandleIssuerKeyAliasEmpty()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, handle_issuer_key_alias_empty_004, testing::ext::TestSize.Level1)
{
    std::unique_ptr<FileUtils> sutils = std::make_unique<FileUtils>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keystoreFile = "/data/test/generateCA/other.p12";
    std::string issuerKeystoreFile = "";
    char keystorepwd[] = "234567";
    char issuerstorepwd[] = "123456";
    (*params)["issuerKeystoreFile"] = issuerKeystoreFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["issuerKeystorePwd"] = issuerstorepwd;
    (*params)["keystorePwd"] = keystorepwd;
    api->HandleIssuerKeyAliasEmpty(params.get());
}


/**
* @tc.name: handle_issuer_key_alias_not_empty_001
* @tc.desc: Test function of HandleIsserKeyAliasNotEmpty()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, handle_issuer_key_alias_not_empty_001, testing::ext::TestSize.Level1)
{
    
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string issuerKeystoreFile = "";
    (*params)["issuerKeystoreFile"] = issuerKeystoreFile;
    api->HandleIsserKeyAliasNotEmpty(params.get());
}

/**
* @tc.name: handle_issuer_key_alias_not_empty_002
* @tc.desc: Test function of HandleIsserKeyAliasNotEmpty()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, handle_issuer_key_alias_not_empty_002, testing::ext::TestSize.Level1)
{

    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string issuerKeystoreFile = "/data/test/generateCA/other.cer";
    (*params)["issuerKeystoreFile"] = issuerKeystoreFile;
    api->HandleIsserKeyAliasNotEmpty(params.get());
}

/**
* @tc.name: generate_end_cert_001
* @tc.desc: Test function of GenerateEndCert()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, generate_end_cert_001, testing::ext::TestSize.Level1)
{

    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerkeyAlias = "oh-app-sign-srv-ca-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateCA/OpenHarmony.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char isksPwd[] = "123456";
    std::string outfile = "/data/test/generateCA/app-release.cer";
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keyStoreFile"] = keystoreFile;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["outFile"] = outfile;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EVP_PKEY* issuerkeyPair = nullptr;
    adaptePtr->SetIssuerKeyStoreFile(true);
    issuerkeyPair = adaptePtr->GetIssureKeyByAlias();
    X509_REQ* csr = nullptr;
    csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateEndCert(csr, issuerkeyPair, *adaptePtr, PROFILE_SIGNING_CAPABILITY, sizeof(PROFILE_SIGNING_CAPABILITY));
    EXPECT_EQ(ret, true);
}


/**
* @tc.name: generate_end_cert_002
* @tc.desc: Test function of GenerateEndCert()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, generate_end_cert_002, testing::ext::TestSize.Level1)
{

    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuerkeyAlias = "oh-app-sign-srv-ca-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateCA/OpenHarmony.p12";
    char keystorePwd[] = "123456";
    std::string signAlg = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char isksPwd[] = "123456";
    std::string outfile = "/data/test/generateCA/app-release.cer";
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keyStoreFile"] = keystoreFile;
    (*params)["signAlg"] = signAlg;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    (*params)["outFile"] = outfile;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EVP_PKEY* issuerkeyPair = nullptr;
    X509_REQ* csr = nullptr;
    csr = CertTools::GenerateCsr(keyPair, signAlg, subject);
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateEndCert(csr, issuerkeyPair, *adaptePtr, PROFILE_SIGNING_CAPABILITY, sizeof(PROFILE_SIGNING_CAPABILITY));
    EXPECT_EQ(ret, true);
}

/**
* @tc.name: issuer_key_store_file_001
* @tc.desc: Test function of IssuerKeyStoreFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, issuer_key_store_file_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "oh-app1-key-v111";
    std::string issuerkeyAlias = "oh-app1-key-v123";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "/data/test/generateCA/OpenHarmony.p12";
    char keystorePwd[] = "123456";
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["issuerKeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    adaptePtr->IssuerKeyStoreFile(&keyPair, true);
}