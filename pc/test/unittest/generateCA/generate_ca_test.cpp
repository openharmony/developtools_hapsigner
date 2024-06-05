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
#include <openssl/ssl.h>
#include <gtest/gtest.h>
#include "signature_tools_log.h"
#include "options.h"
#include "sign_tool_service_impl.h"
#include "cert_tools.h"
#include "hap_sign_tool.h"
#include "localization_adapter.h"
#include "fs_digest_utils.h"
#include "hash.h"
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
    int keysize = 384;
    char secret[] = "adhjkljasjhdk";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keysize"] = keysize;
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
    int keysize = 384;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keysize"] = keysize;
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
    int keysize = 384;
    int validity = 365;
    int basicConstraintsPathLen = 0;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keysize"] = keysize;
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
    int keysize = 384;
    int validity = 365;
    int basicConstraintsPathLen = 0;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keysize"] = keysize;
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
    int keysize = 384;
    int validity = 365;
    int basicConstraintsPathLen = 0;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keysize"] = keysize;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["validity"] = validity;
    (*params)["basicConstraintsPathLen"] = basicConstraintsPathLen;
    (*params)["outFile"] = outFile;

    bool ret = api->GenerateCA(params.get());
    EXPECT_EQ(ret, false);
}
/**
 * @tc.name: generate_subca_test_001
 * @tc.desc: Test function of GenerateCa()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_subca_test_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    EXPECT_NE(csr, nullptr);
    bool ret = CertTools::GenerateSubCert(keyPair, csr, params.get());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: generate_subca_test_002
 * @tc.desc: Test function of GenerateCa()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_subca_test_002, testing::ext::TestSize.Level1)
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
    std::string outFile = "/data/test/generateCA/subca.cer";
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    int keysize = 384;
    char secret[] = "123456";
    char ksPwd[] = "123456";
    char isksPwd[] = "123456";
    (*params)["keyPwd"] = secret;
    (*params)["keystorePwd"] = ksPwd;
    (*params)["issuerkeystorePwd"] = isksPwd;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keysize"] = keysize;
    (*params)["subject"] = subject;
    (*params)["issuer"] = issuer;
    (*params)["signAlg"] = signAlg;
    (*params)["keyStoreFile"] = keyStoreFile;
    (*params)["issuerkeyStoreFile"] = issuerkeystroefile;
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
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    (*params)["keyPwd"] = secret;
    (*params)["issuerkeystorePwd"] = isksPwd;
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    std::string outFile = "./generateCA/rootCa.cer";
    (*params)["keyPwd"] = secret;
    (*params)["issuerkeystorePwd"] = isksPwd;
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
    int keysize = 384;
    (*params)["keyAlias"] = keyAlias;
    (*params)["issuerKeyAlias"] = issuerKeyAlias;
    (*params)["keysize"] = keysize;
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    (*params)["issuerkeystorePwd"] = isksPwd;
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    (*params)["issuerkeystorePwd"] = isksPwd;
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
    std::string outFile = "general.cer";
    bool basicConstraints = true;
    bool basicConstraintsCritical = true;
    bool basicConstraintsCa = true;
    bool keyUsageCritical = true;
    char secret[] = "123456";
    char keystorePwd[] = "123456";
    int keysize = 384;
    (*params)["keysize"] = keysize;
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
 * @tc.name: generate_cert_test_007
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_007, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
 * @tc.name: generate_cert_test_008
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_008, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
 * @tc.name: generate_cert_test_009
 * @tc.desc: Test function of GenerateCert()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_cert_test_009, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
 * @tc.name: generate_cert_test_0010
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
 * @tc.desc: Test function of GenerateAppCert()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_001, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string caCertFile = "/data/test/generateCA/root-ca1.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1.cer";
    std::string outFile = "/data/test/generateCA/test-profile-cert-v1.cer";
    const char secret[] = "123456";
    const char ksPwd[] = "123456";
    const char isksPwd[] = "123456";
    const char isskeypwd[] = "123456";
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
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string caCertFile = "/data/test/generateCA/root-ca1.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1.cer";
    const char secret[] = "123456";
    const char ksPwd[] = "123456";
    const char isksPwd[] = "123456";
    const char isskeypwd[] = "123456";
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
    params[Options::OUT_FORM] = outForm;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_app_cert_test_003
 * @tc.desc: Test function of GenerateAppCert()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_003, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outForm = "cert";
    std::string outFile = "/data/test/generateCA/test-app-cert-v1.cer";
    const char secret[] = "123456";
    const char ksPwd[] = "123456";
    const char isksPwd[] = "123456";
    const char isskeypwd[] = "123456";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;
    params[Options::OUT_FORM] = outForm;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_app_cert_test_004
 * @tc.desc: Test function of GenerateAppCert()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_004, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outForm = "cert";
    const char secret[] = "123456";
    const char ksPwd[] = "123456";
    const char isksPwd[] = "123456";
    const char isskeypwd[] = "123456";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FORM] = outForm;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_app_cert_test_005
 * @tc.desc: Test function of GenerateAppCert()  interface for cert FALIED.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_005, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outForm = "cert";
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_app_cert_test_006
 * @tc.desc: Test function of GenerateAppCert()  interface for certchain FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_006, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string caCertFile = "/data/test/generateCA/test-app-cert-v1.cer";
    std::string subCaCertFile = "/data/test/generateCA/test-app-cert-v1.cer";
    const char secret[] = "123456";
    const char ksPwd[] = "123456";
    const char isksPwd[] = "123456";
    const char isskeypwd[] = "123456";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::CA_CERT_FILE] = caCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;

    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_app_cert_test_007
 * @tc.desc: Test function of GenerateAppCert()  interface for certchain FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_007, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string issuerKeyAlias = "";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/app-release1.pem";
    const char secret[] = "123456";
    const char ksPwd[] = "123456";
    const char isksPwd[] = "123456";
    const char isskeypwd[] = "123456";
    params[Options::KEY_RIGHTS] = secret;
    params[Options::KEY_STORE_RIGHTS] = ksPwd;
    params[Options::ISSUER_KEY_RIGHTS] = isksPwd;
    params[Options::ISSUER_KEY_STORE_RIGHTS] = isskeypwd;
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_app_cert_test_008
 * @tc.desc: Test function of GenerateAppCert()  interface for CERTCHAIN FAILED.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_008, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outForm = "cert";

    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;

    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_app_cert_test_009
 * @tc.desc: Test function of GenerateAppCert()  interface for certchain FAILED.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_009, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/app-release1.pem";
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;

    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_app_cert_test_0010
 * @tc.desc: Test function of GenerateAppCert()  interface for certchain FAILED.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_appcert_test_010, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "";
    std::string outFile = "/data/test/generateCA/app-release1.pem";
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::OUT_FILE] = outFile;
    bool result = api.GenerateAppCert(&params);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: generate_profile_cert_test_001
 * @tc.desc: Test function of GenerateProfileCert()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profile_cert_test_001, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string caCertFile = "/data/test/generateCA/root-ca1.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1.cer";
    std::string outFile = "/data/test/generateCA/test-profile-cert-v1.cer";
    std::string outForm = "certChain";
    const char secret[] = "123456";
    const char ksPwd[] = "123456";
    const char isksPwd[] = "123456";
    const char isskeypwd[] = "123456";
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
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_profile_cert_test_002
 * @tc.desc: Test function of GenerateProfileCert()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profile_cert_test_002, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA";
    std::string issuerKeyAlias = "oh-app1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string caCertFile = "/data/test/generateCA/root-ca1.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1.cer";
    std::string outForm = "certChain";
    const char secret[] = "123456";
    const char ksPwd[] = "123456";
    const char isksPwd[] = "123456";
    const char isskeypwd[] = "123456";
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
    params[Options::OUT_FORM] = outForm;
    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, true);
}
/**
 * @tc.name: generate_profile_cert_test_003
 * @tc.desc: Test function of GenerateProfileCert()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profile_cert_test_003, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Profile SUB  CA";
    std::string issuerKeyAlias = "oh-profile1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Profile CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outForm = "cert";
    std::string outFile = "/data/test/generateCA/test-profile-cert-v1.cer";
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;

    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_profile_cert_test_004
 * @tc.desc: Test function of GenerateProfileCert()  interface for cert SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profile_cert_test_004, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Profile SUB  CA";
    std::string issuerKeyAlias = "oh-profile1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Profile CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outForm = "cert";
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;

    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_profile_cert_test_005
 * @tc.desc: Test function of GenerateProfileCert()  interface for cert FALIED.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profile_cert_test_005, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
    std::string issuerKeyAlias = "oh-profile1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outForm = "cert";

    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    // params[Options::KEY_STORE_FILE] = keyStoreFile;

    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_profile_cert_test_006
 * @tc.desc: Test function of GenerateProfileCert()  interface for certchain SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profile_cert_test_006, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Profile SUB  CA";
    std::string issuerKeyAlias = "oh-profile1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Profile CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string caCertFile = "/data/test/generateCA/root-ca1.cer";
    std::string subCaCertFile = "/data/test/generateCA/profile-sign-srv-ca1.cer";

    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::CA_CERT_FILE] = caCertFile;
    params[Options::SUB_CA_CERT_FILE] = subCaCertFile;

    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_profile_cert_test_007
 * @tc.desc: Test function of GenerateProfileCert()  interface for certchain SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_prodile_cert_test_007, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Profile SUB  CA";
    std::string issuerKeyAlias = "oh-issuer-profile1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Profile CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outFile = "/data/test/generateCA/test-profile1-cert-v1.pem";
    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;
    params[Options::KEY_STORE_FILE] = keyStoreFile;
    params[Options::OUT_FILE] = outFile;

    bool result = api.GenerateProfileCert(&params);
    EXPECT_EQ(result, false);
}
/**
 * @tc.name: generate_profile_cert_test_008
 * @tc.desc: Test function of GenerateProfileCert()  interface for CERTCHAIN FAILED.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, generate_profile_cert_test_008, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options params;
    std::string keyAlias = "oh-profile1-key-v1";
    std::string issuer = "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Profile SUB  CA";
    std::string issuerKeyAlias = "oh-profile1-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Profile CA";
    std::string signAlg = "SHA384withECDSA";
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    std::string outForm = "certChain";

    params[Options::KEY_ALIAS] = keyAlias;
    params[Options::ISSUER] = issuer;
    params[Options::ISSUER_KEY_ALIAS] = issuerKeyAlias;
    params[Options::SUBJECT] = subject;
    params[Options::SIGN_ALG] = signAlg;

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
    char keyStorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keyStoreFile;
    (*params)["keystorePwd"] = keyStorePwd;
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
    char keyStorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string basicConstraintsPathLen = "5";
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keyStoreFile;
    (*params)["keystorePwd"] = keyStorePwd;
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
    char keyStorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    int validity = 3650;
    params["keyAlias"] = keyAlias;
    params["keyPwd"] = keyPwd;
    params["keySize"] = keySize;
    params["keystoreFile"] = keyStoreFile;
    params["keystorePwd"] = keyStorePwd;
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
    X509_NAME* name = X509_NAME_new();
    X509* cert = CertTools::GenerateEndCert(csr, keyPair, adapter, appSigningCapability,
                                            sizeof(appSigningCapability), name);
    X509_NAME_free(name);
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
    const char appSigningCapability[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x0A, 0x01, 0x00 };
    Options params;
    char keyPwd[] = "123456";
    int keySize = 256;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char keyStorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA384withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    params["keyPwd"] = keyPwd;
    params["keySize"] = keySize;
    params["keystoreFile"] = keyStoreFile;
    params["keystorePwd"] = keyStorePwd;
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
    X509_NAME* name = X509_NAME_new();
    X509* cert = CertTools::GenerateEndCert(csr, keyPair, adapter, appSigningCapability,
                                            sizeof(appSigningCapability), name);
    X509_NAME_free(name);
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
    const char appSigningCapability[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x0A, 0x01, 0x00 };
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string keyAlias = "alias";
    char keyPwd[] = "123456";
    int keySize = 256;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char keyStorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keyStoreFile;
    (*params)["keystorePwd"] = keyStorePwd;
    (*params)["algorithm"] = algorithm;
    (*params)["signAlgorithm"] = signAlgorithm;
    (*params)["subject"] = subject;
    LocalizationAdapter adapter(params.get());
    std::shared_ptr<KeyStoreHelper> keyStoreHelper = std::make_shared<KeyStoreHelper>();
    EVP_PKEY* keyPair = keyStoreHelper->GenerateKeyPair(algorithm, keySize);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509_NAME* name = X509_NAME_new();
    X509* cert = CertTools::GenerateEndCert(csr, keyPair, adapter, appSigningCapability,
                                            sizeof(appSigningCapability), name);
    X509_NAME_free(name);
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
    const char appSigningCapability[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x0A, 0x01, 0x00 };
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    int keySize = 256;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char keyStorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    int validity = 3650;
    params["keyAlias"] = keyAlias;
    params["keyPwd"] = keyPwd;
    params["keySize"] = keySize;
    params["keystoreFile"] = keyStoreFile;
    params["keystorePwd"] = keyStorePwd;
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
    X509_NAME* name = X509_NAME_new();
    X509* cert = CertTools::GenerateEndCert(csr, keyPair, adapter, appSigningCapability,
                                            sizeof(appSigningCapability), name);
    X509_NAME_free(name);
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
    const char appSigningCapability[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x0A, 0x01, 0x00 };
    Options params;
    std::string keyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    int keySize = 256;
    std::string keyStoreFile = "/data/test/generateCA/ohtest.p12";
    char keyStorePwd[] = "123456";
    std::string algorithm = "ECC";
    std::string signAlgorithm = "SHA256withECDSA";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    int validity = 3650;
    params["keyAlias"] = keyAlias;
    params["keyPwd"] = keyPwd;
    params["keySize"] = keySize;
    params["keystoreFile"] = keyStoreFile;
    params["keystorePwd"] = keyStorePwd;
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
    X509_NAME* name = X509_NAME_new();
    X509* cert = CertTools::GenerateEndCert(csr, keyPair, adapter, appSigningCapability,
                                            sizeof(appSigningCapability), name);
    X509_NAME_free(name);
    EXPECT_NE(cert, nullptr);
    bool ret = api.OutPutCert(cert, " ");
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
 * @tc.desc: Test function of PrintX509FromMemory()  interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, print_x509_test_001, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    X509* cert1 = X509_new();
    bool ret = api.PrintX509FromMemory(cert1);
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
 * @tc.name: hap_verify_test_001
 * @tc.desc: Test function of VerifyHap()  interface for cert SUCCESS.
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
    bool result = api.VerifyHap(&params);
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
    const char secret[] = "123456";
    const char ksPwd[] = "123456";
    const char isksPwd[] = "123456";
    const char isskeypwd[] = "123456";
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
    const char secret[] = "123456";
    const char ksPwd[] = "123456";
    const char isksPwd[] = "123456";
    const char isskeypwd[] = "123456";
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
    EVP_PKEY* issueKeyPair = adapter.GetKeyPair(true);
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
    const char secret[] = "123456";
    const char ksPwd[] = "123456";
    const char isksPwd[] = "123456";
    const char isskeypwd[] = "123456";
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
    const char isskeypwd[] = { 0 };
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
    X509* cert1 = CertTools::SetExpandedInfExtOne(cert, params.get(), critical, ext1);
    EXPECT_NE(cert1, nullptr);
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
    X509* cert1 = CertTools::SetExpandedInfExtOne(cert, params.get(), critical, ext1);
    EXPECT_NE(cert1, nullptr);
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
    X509* cert1 = CertTools::SetExpandedInfExtTwo(cert, params.get(), critical, ext2);
    EXPECT_NE(cert1, nullptr);
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
    X509* cert1 = CertTools::SetExpandedInfExtTwo(cert, params.get(), critical, ext2);
    EXPECT_NE(cert1, nullptr);
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
    X509* cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, nullptr);
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
    X509* cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, nullptr);
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
    X509* cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, nullptr);
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
    X509* cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, nullptr);
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
    X509* cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, nullptr);
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
    X509* cert1 = CertTools::SetExpandedInfExtThree(cert, params.get(), critical, ext3);
    EXPECT_NE(cert1, nullptr);
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_NE(cert, nullptr);
    bool ret = api->GenerateSubCertToFile(params.get(), keyPair, cert);
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
    std::string signAlgorithm = "SHA256withECDSA";
    int keySize = 256;
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_NE(cert, nullptr);
    bool ret = api->GenerateSubCertToFile(params.get(), keyPair, cert);
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
    std::string signAlgorithm = "SHA256withECDSA";
    int keySize = 256;
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    (*params)["signAlgorithm"] = signAlgorithm;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_EQ(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_NE(cert, nullptr);
    bool ret = api->GenerateSubCertToFile(params.get(), keyPair, cert);
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
    std::string signAlgorithm = "SHA256withECDSA";
    int keySize = 256;
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    (*params)["signAlgorithm"] = signAlgorithm;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_NE(cert, nullptr);
    bool ret = api->GenerateSubCertToFile(params.get(), keyPair, cert);
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
    std::string signAlgorithm = "SHA256withECDSA";
    int keySize = 256;
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    (*params)["signAlgorithm"] = signAlgorithm;
    (*params)["issuerkeyAlias"] = issuerkeyAlias;
    std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());
    EVP_PKEY* keyPair = nullptr;
    keyPair = adaptePtr->GetAliasKey(true);
    EXPECT_NE(keyPair, nullptr);
    X509_REQ* csr = CertTools::GenerateCsr(keyPair, signAlgorithm, subject);
    EXPECT_NE(csr, nullptr);
    X509* cert = CertTools::GenerateRootCertificate(keyPair, csr, params.get());
    EXPECT_NE(cert, nullptr);
    bool ret = api->GenerateSubCertToFile(params.get(), keyPair, cert);
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    X509* cert1 = CertTools::SetPubkeyAndSignCert(cert, issuercsr, csr, keyPair, params.get());
    EXPECT_NE(cert1, nullptr);
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    X509* cert1 = CertTools::SetPubkeyAndSignCert(cert, issuercsr, csr, keyPair, params.get());
    EXPECT_NE(cert1, nullptr);
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
    std::string signAlgorithm = "SHA256withECDSA";
    int keySize = 256;
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    X509_REQ* csr = X509_REQ_new();
    EXPECT_EQ(csr, nullptr);
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlgorithm, issuer);
    EXPECT_NE(issuercsr, nullptr);
    X509* cert = nullptr;
    EXPECT_EQ(cert, nullptr);
    X509* cert1 = CertTools::SetPubkeyAndSignCert(cert, issuercsr, csr, keyPair, params.get());
    EXPECT_NE(cert1, nullptr);
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

// /**
//  * @tc.name: sign_cert_test_001
//  * @tc.desc: Test function of SignCert()  interface for FAIL.
//  * @tc.type: FUNC
//  * @tc.require: SR000H63TL
//  */
// HWTEST_F(GenerateCaTest, sign_cert_test_001, testing::ext::TestSize.Level1)
// {
//     X509* cert = X509_new();
//     EVP_PKEY* key = EVP_PKEY_new();
//     bool res = CertTools::SignCert(cert, key, "SHA256withECDSA");
//     X509_free(cert);
//     EVP_PKEY_free(key);
//     EXPECT_EQ(res, false);
// }
// /**
//  * @tc.name: sign_cert_test_002
//  * @tc.desc: Test function of SignCert()  interface for FAIL.
//  * @tc.type: FUNC
//  * @tc.require: SR000H63TL
//  */
// HWTEST_F(GenerateCaTest, sign_cert_test_002, testing::ext::TestSize.Level1)
// {
//     X509* cert = X509_new();
//     EVP_PKEY* key = EVP_PKEY_new();
//     bool res = CertTools::SignCert(cert, key, "SHA384withECDSA");
//     X509_free(cert);
//     EVP_PKEY_free(key);
//     EXPECT_EQ(res, false);
// }
/**
 * @tc.name: handle_test_001
 * @tc.desc: Test function of SignCert()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, handle_test_001, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options options;
    char secret[] = "123456";
    options[Options::ISSUER_KEY_RIGHTS] = secret;
    options[Options::ISSUER_KEY_STORE_FILE] = "";
    bool res = api.HandleIsserKeyAliasNotEmpty(&options);
    EXPECT_EQ(res, false);
}
/**
 * @tc.name: handle_test_002
 * @tc.desc: Test function of SignCert()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, handle_test_002, testing::ext::TestSize.Level1)
{
    SignToolServiceImpl api;
    Options options;
    char secret[] = "123456";
    options[Options::ISSUER_KEY_RIGHTS] = secret;
    options[Options::ISSUER_KEY_STORE_FILE] = "11.p12";
    bool res = api.HandleIsserKeyAliasNotEmpty(&options);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: handle_isser_keyAlias_not_empty_test_001
 * @tc.desc: Test function of HandleIsserKeyAliasNotEmpty()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, handle_isser_keyAlias_not_empty_test_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::string issuerkeystroefile = "/data/test/generateCA/ohtest.p12";
    char isksPwd[7] = "abcdef";
    (*params)["issuerKeystorePwd"] = isksPwd;
    (*params)["issuerkeyStoreFile"] = issuerkeystroefile;
    bool ret = api->HandleIsserKeyAliasNotEmpty(params.get());
    EXPECT_EQ(ret, false);
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    X509* cert = X509_new();
    std::shared_ptr<Options> params = std::make_shared<Options>();
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::string keyAlias = "alias";
    std::string issuerkeyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 256;
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    X509* cert1 = CertTools::SignForSubCert(cert, csr, issuercsr, keyPair, params.get());
    EVP_PKEY* NewkeyPair = nullptr;
    bool ret = api->X509CertVerify(cert1, NewkeyPair);
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
    std::ifstream file("./generateKeyPair/keypair.p12");
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
    std::ifstream file("./");
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
    std::ifstream file("./");
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
    std::ifstream file("./generateKeyPair/keypair.p12");
    std::ofstream out("./generateKeyPair/test.txt");
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
    std::ifstream file("./generateKeyPair/keypair.p12");
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
    std::ofstream outFile("./test.txt");
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
    std::string path = "./";
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
    std::string outFile = "./test.txt";
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
    bool res = HapVerifyOpensslUtils::ParsePkcs7Package(packageData, 10, pkcs7Context);
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
    bool res = HapVerifyOpensslUtils::ParsePkcs7Package(packageData, 10, pkcs7Context);
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
    bool ret = HapVerifyOpensslUtils::GetCertChains(p7, pkcs7Context);
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
    bool ret = HapVerifyOpensslUtils::GetCertChains(p7, pkcs7Context);
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
    X509* cert1 = CertTools::SetBisicConstraintsPatchLen(&options, cert);
    EXPECT_NE(cert1, nullptr);
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    X509* cert1 = CertTools::SignForSubCert(cert, csr, issuercsr, keyPair, params.get());

    EXPECT_NE(cert1, nullptr);
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    X509_REQ* csr = nullptr;
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlg, issuer);
    X509* cert1 = CertTools::SignForSubCert(cert, csr, issuercsr, keyPair, params.get());
    EXPECT_EQ(cert1, nullptr);
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
    std::string keystoreFile = "./generateKeyPair/keypair.p12";
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
    X509_REQ* issuercsr = CertTools::GenerateCsr(keyPair, signAlg, issuer);
    X509* cert1 = CertTools::SignForSubCert(cert, csr, issuercsr, keyPair, params.get());

    EXPECT_NE(cert1, nullptr);
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
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
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
 * @tc.name: set_subject_for_cert_test_001
 * @tc.desc: Test function of CertTools::SetSubjectForCert()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, set_subject_for_cert_test_001, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    X509_REQ* csr = X509_REQ_new();
    X509* cert1 = CertTools::SetSubjectForCert(csr, cert);
    EXPECT_EQ(cert1, nullptr);
}

/**
 * @tc.name: contains_ignore_case_test_001
 * @tc.desc: Test function of CertTools::ContainsIgnoreCase()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, contains_ignore_case_test_001, testing::ext::TestSize.Level1)
{
    std::vector<std::string> strs;
    std::string a = "abc";
    std::string b = "bcd";
    std::string c = "cde";
    std::string d = "efg";
    strs.push_back(a);
    strs.push_back(b);
    strs.push_back(c);
    strs.push_back(d);
    std::string str = "abc";
    bool ret = StringUtils::ContainsIgnoreCase(strs, str);
    EXPECT_EQ(ret, true);
}


/**
 * @tc.name: contains_ignore_case_test_002
 * @tc.desc: Test function of CertTools::ContainsIgnoreCase()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, contains_ignore_case_test_002, testing::ext::TestSize.Level1)
{
    std::vector<std::string> strs;
    std::string a = "abc";
    std::string b = "bcd";
    std::string c = "cde";
    std::string d = "efg";
    strs.push_back(a);
    strs.push_back(b);
    strs.push_back(c);
    strs.push_back(d);
    std::string str = "mntee";
    bool ret = StringUtils::ContainsIgnoreCase(strs, str);
    EXPECT_EQ(ret, false);
}
/**
 * @tc.name: isempty_test_002
 * @tc.desc: Test function of IsEmpty()  interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(GenerateCaTest, isempty_test_003, testing::ext::TestSize.Level1)
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
    int res = FileUtils::Write(cs, "./");
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
    std::string file = "./";
    std::ofstream out("");
    bool res = FileUtils::AppendWriteFileByOffsetToFile(file, out, 10, 100);
    EXPECT_EQ(res, false);
}
/**
* @tc.name: Append_Write_File_ByOffset_To_File_test_005
* @tc.desc: Test function of AppendWriteFileByOffsetToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Append_Write_File_ByOffset_To_File_test_005, testing::ext::TestSize.Level1)
{
    std::string file = "./generateKeyPair/keypair.p12";
    std::ofstream out("./generateKeyPair/test.txt");
    bool res = FileUtils::AppendWriteFileByOffsetToFile(file, out, 10, 100);
    EXPECT_EQ(res, false);
}
/**
* @tc.name: Append_Write_File_ByOffset_To_File_test_006
* @tc.desc: Test function of AppendWriteFileByOffsetToFile()  interface for FAIL.
* @tc.type: FUNC
* @tc.require: SR000H63TL
*/
HWTEST_F(GenerateCaTest, Append_Write_File_ByOffset_To_File_test_006, testing::ext::TestSize.Level1)
{
    std::string file = "./";
    std::ofstream out("./generateKeyPair/test.txt");
    bool res = FileUtils::AppendWriteFileByOffsetToFile(file, out, 10, 100);
    EXPECT_EQ(res, false);
}