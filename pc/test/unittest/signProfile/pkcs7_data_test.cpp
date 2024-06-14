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
#include <chrono>
#include <thread>
#include <string>

#include "gtest/gtest.h"
#include "options.h"
#include "sign_tool_service_impl.h"
#include "nlohmann/json.hpp"
#include "signer_factory.h"
#include "profile_sign_tool.h"
#include "params_run_tool.h"
#include "pkcs7_data.h"
#include "signer_config.h"
#include "local_signer.h"
#include "bc_pkcs7_generator.h"
#include "bc_signeddata_generator.h"
#include "profile_verify.h"

using  nlohmann::json;

namespace OHOS {
namespace SignatureTools {
// sign profile使用的全局参数
static const std::string SIGN_PROFILE_MODE = "localSign";
static const std::string SIGN_PROFILE_KEY_ALIAS = "oh-profile1-key-v1";
static const std::string SIGN_PROFILE_PROFILE_CERT_FILE = "./signProfile/profile-release1.pem";
static const std::string SIGN_PROFILE_SIGN_ALG = "SHA384withECDSA";
static const std::string SIGN_PROFILE_KEY_STORE_FILE = "./signProfile/ohtest.p12";
static const std::string SIGN_PROFILE_OUT_FILE = "./signProfile/signed-profile.p7b";
static const std::string SIGN_PROFILE_IN_FILE = "./signProfile/profile.json";

// static const std::string SIGN_PROFILE_CERT_PEM = "./signProfile/profile-release1-cert.pem";
// static const std::string SIGN_PROFILE_REVERSE_PEM = "./signProfile/profile-release1-reverse.pem";
// static const std::string SIGN_PROFILE_DOUBLE_CERT_PEM = "./signProfile/"
//                                                         "profile-release1-invalid_cert_chain.pem";

class Pkcs7DataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp()override;
    void TearDown()override;
};
void Pkcs7DataTest::SetUpTestCase(void)
{
}

void Pkcs7DataTest::TearDownTestCase(void)
{
}

void Pkcs7DataTest::SetUp()
{
}

void Pkcs7DataTest::TearDown()
{
}

// cert verify cert NULL
HWTEST_F(Pkcs7DataTest, pkcs7_test001, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    X509* issuerCert = X509_new();
    int result=PKCS7Data::CertVerify(NULL, issuerCert);
    X509_free(cert);
    X509_free(issuerCert);
    EXPECT_FALSE(result == 0);
}

// cert verify issuerCert NULL
HWTEST_F(Pkcs7DataTest, pkcs7_test002, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    X509* issuerCert = X509_new();
    int result = PKCS7Data::CertVerify(cert, NULL);
    X509_free(cert);
    X509_free(issuerCert);
    EXPECT_FALSE(result == 0);
}

// cert verify pubkey NULL
HWTEST_F(Pkcs7DataTest, pkcs7_test003, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    X509* issuerCert = X509_new();
    int result = PKCS7Data::CertVerify(cert, issuerCert);
    X509_free(cert);
    X509_free(issuerCert);
    EXPECT_FALSE(result == 0);
}

// cert verify pubkey NULL
HWTEST_F(Pkcs7DataTest, pkcs7_test004, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    X509* issuerCert = X509_new();
    int result = PKCS7Data::CertVerify(cert, issuerCert);
    X509_free(cert);
    X509_free(issuerCert);
    EXPECT_FALSE(result == 0);
}

// cert verify failed
HWTEST_F(Pkcs7DataTest, pkcs7_test005, testing::ext::TestSize.Level1)
{
    Options options;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::MODE] = SIGN_PROFILE_MODE;
    options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_PROFILE_CERT_FILE;
    options[Options::SIGN_ALG] = SIGN_PROFILE_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
    options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    SignerFactory factory;
    std::shared_ptr<Signer> signer = factory.GetSigner(adapter);
    STACK_OF(X509)*certs= signer->GetCertificates();
    PKCS7Data::ReverseX509Stack(certs);
    int result=PKCS7Data::CertVerify(sk_X509_value(certs, 0), sk_X509_value(certs, 1));
    PKCS7Data::PrintCertChainSub(certs);
    EXPECT_FALSE(result == 0);
}

// X509 stack sort certsNum 0
HWTEST_F(Pkcs7DataTest, pkcs7_test006, testing::ext::TestSize.Level1)
{
    STACK_OF(X509)*certs=sk_X509_new(NULL);
    PKCS7Data::SortX509Stack(certs);
    sk_X509_free(certs);
    EXPECT_TRUE(true);
}

// get asn1 time
HWTEST_F(Pkcs7DataTest, pkcs7_test007, testing::ext::TestSize.Level1)
{
    ASN1_TIME*time=ASN1_TIME_new();
    ASN1_TIME_set(time, -1);
    std::string result=PKCS7Data::GetASN1Time(time);
    ASN1_TIME_free(time);
    EXPECT_TRUE(result.empty());
}

// empty x509Name
HWTEST_F(Pkcs7DataTest, pkcs7_test008, testing::ext::TestSize.Level1)
{
    std::string text;
    PKCS7Data::GetTextFromX509Name(NULL, 45, text);
    EXPECT_TRUE(text.empty());
}

// GetDnToString
HWTEST_F(Pkcs7DataTest, pkcs7_test009, testing::ext::TestSize.Level1)
{
    std::string result=PKCS7Data::GetDnToString(NULL);
    EXPECT_TRUE(result.empty());
}

// GetSubjectFromX509
HWTEST_F(Pkcs7DataTest, pkcs7_test010, testing::ext::TestSize.Level1)
{
    std::string subject;
    int result = PKCS7Data::GetSubjectFromX509(NULL, subject);
    EXPECT_TRUE(result < 0);
}

// X509NameCompare
HWTEST_F(Pkcs7DataTest, pkcs7_test011, testing::ext::TestSize.Level1)
{
    int result=PKCS7Data::X509NameCompare(NULL, NULL);
    EXPECT_EQ(result, false);
}

// X509NameCompare
HWTEST_F(Pkcs7DataTest, pkcs7_test012, testing::ext::TestSize.Level1)
{
    Options options;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::MODE] = SIGN_PROFILE_MODE;
    options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_PROFILE_CERT_FILE;
    options[Options::SIGN_ALG] = SIGN_PROFILE_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
    options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    SignerFactory factory;
    std::shared_ptr<Signer> signer = factory.GetSigner(adapter);
    STACK_OF(X509)* certs = signer->GetCertificates();
    int result = PKCS7Data::X509NameCompare(sk_X509_value(certs, 0),NULL);
    EXPECT_EQ(result, false);
}

// X509NameCompare
HWTEST_F(Pkcs7DataTest, pkcs7_test013, testing::ext::TestSize.Level1)
{
    Options options;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::MODE] = SIGN_PROFILE_MODE;
    options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_PROFILE_CERT_FILE;
    options[Options::SIGN_ALG] = SIGN_PROFILE_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
    options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    SignerFactory factory;
    std::shared_ptr<Signer> signer = factory.GetSigner(adapter);
    STACK_OF(X509)* certs = signer->GetCertificates();
    int result = PKCS7Data::X509NameCompare(sk_X509_value(certs, 0), sk_X509_value(certs, 1));
    EXPECT_EQ(result, true);
}
}
}