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

// verify profile 使用的全局参数
static const std::string VERIFY_PROFILE_IN_FILE = "./signProfile/signed-profile.p7b";
static const std::string VERIFY_PROFILE_OUT_FILE = "./signProfile/verify-result.json";

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
    bool result = VerifyCertOpensslUtils::CertVerify(NULL, issuerCert);
    X509_free(cert);
    X509_free(issuerCert);
    EXPECT_FALSE(result);
}

// cert verify issuerCert NULL
HWTEST_F(Pkcs7DataTest, pkcs7_test002, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    X509* issuerCert = X509_new();
    bool result = VerifyCertOpensslUtils::CertVerify(cert, NULL);
    X509_free(cert);
    X509_free(issuerCert);
    EXPECT_FALSE(result);
}

// cert verify pubkey NULL
HWTEST_F(Pkcs7DataTest, pkcs7_test003, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    X509* issuerCert = X509_new();
    bool result = VerifyCertOpensslUtils::CertVerify(cert, issuerCert);
    X509_free(cert);
    X509_free(issuerCert);
    EXPECT_FALSE(result);
}

// cert verify pubkey NULL
HWTEST_F(Pkcs7DataTest, pkcs7_test004, testing::ext::TestSize.Level1)
{
    X509* cert = X509_new();
    X509* issuerCert = X509_new();
    bool result = VerifyCertOpensslUtils::CertVerify(cert, issuerCert);
    X509_free(cert);
    X509_free(issuerCert);
    EXPECT_FALSE(result);
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
    STACK_OF(X509)* certs = signer->GetCertificates();
    PKCS7Data::ReverseX509Stack(certs);
    bool result = VerifyCertOpensslUtils::CertVerify(sk_X509_value(certs, 0), sk_X509_value(certs, 1));
    PKCS7Data::PrintCertChainSub(certs);
    EXPECT_FALSE(result);
}

// X509 stack sort certsNum 0
HWTEST_F(Pkcs7DataTest, pkcs7_test006, testing::ext::TestSize.Level1)
{
    STACK_OF(X509)* certs = sk_X509_new(NULL);
    PKCS7Data::SortX509Stack(certs);
    sk_X509_free(certs);
    EXPECT_TRUE(true);
}

// get asn1 time
HWTEST_F(Pkcs7DataTest, pkcs7_test007, testing::ext::TestSize.Level1)
{
    ASN1_TIME* time = ASN1_TIME_new();
    ASN1_TIME_set(time, -1);
    std::string result = PKCS7Data::GetASN1Time(time);
    ASN1_TIME_free(time);
    EXPECT_TRUE(result.empty());
}

// empty x509Name
HWTEST_F(Pkcs7DataTest, pkcs7_test008, testing::ext::TestSize.Level1)
{
    std::string text;
    VerifyCertOpensslUtils::GetTextFromX509Name(NULL, 45, text);
    EXPECT_TRUE(text.empty());
}

// GetDnToString
HWTEST_F(Pkcs7DataTest, pkcs7_test009, testing::ext::TestSize.Level1)
{
    std::string result = VerifyCertOpensslUtils::GetDnToString(NULL);
    EXPECT_TRUE(result.empty());
}

// GetSubjectFromX509
HWTEST_F(Pkcs7DataTest, pkcs7_test010, testing::ext::TestSize.Level1)
{
    std::string subject;
    bool result = VerifyCertOpensslUtils::GetSubjectFromX509(NULL, subject);
    EXPECT_FALSE(result);
}

// X509NameCompare
HWTEST_F(Pkcs7DataTest, pkcs7_test011, testing::ext::TestSize.Level1)
{
    int result = PKCS7Data::X509NameCompare(NULL, NULL);
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
    int result = PKCS7Data::X509NameCompare(sk_X509_value(certs, 0), NULL);
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

// pkcs7Data parse
HWTEST_F(Pkcs7DataTest, pkcs7_test014, testing::ext::TestSize.Level1)
{
    PKCS7Data p7Data;
    unsigned char buf[15] = "hello";
    const unsigned char* p = buf;
    int len = 5;
    std::string p7b(p, p + len);
    int result = p7Data.Parse(p7b);
    EXPECT_TRUE(result < 0);
}

// pkcs7Data parse check sign time
HWTEST_F(Pkcs7DataTest, pkcs7_test015, testing::ext::TestSize.Level1)
{
    ASN1_TYPE* signTime = NULL;
    ASN1_TIME* notBefore = NULL;
    ASN1_TIME* notAfter = NULL;
    PKCS7Data p7Data;
    PKCS7Data::CheckSignTimeInValidPeriod(signTime, notBefore, notAfter);
}

// pkcs7Data check sign time
HWTEST_F(Pkcs7DataTest, pkcs7_test016, testing::ext::TestSize.Level1)
{
    ASN1_TYPE* signTime = NULL;
    ASN1_TIME notBefore{ 0 };
    notBefore.data = NULL;
    ASN1_TIME* notAfter = NULL;
    PKCS7Data p7Data;
    int result = PKCS7Data::CheckSignTimeInValidPeriod(signTime, &notBefore, notAfter);
    EXPECT_TRUE(result < 0);
}

// pkcs7Data check sign time
HWTEST_F(Pkcs7DataTest, pkcs7_test017, testing::ext::TestSize.Level1)
{
    unsigned char data[5] = "hell";
    ASN1_TYPE* signTime = NULL;
    ASN1_TIME notBefore{ 0 };
    notBefore.data = data;
    ASN1_TIME* notAfter = NULL;
    PKCS7Data p7Data;
    int result = PKCS7Data::CheckSignTimeInValidPeriod(signTime, &notBefore, notAfter);
    EXPECT_TRUE(result < 0);
}

// pkcs7Data check sign time
HWTEST_F(Pkcs7DataTest, pkcs7_test018, testing::ext::TestSize.Level1)
{
    unsigned char data[5] = "hell";
    ASN1_TYPE* signTime = NULL;
    ASN1_TIME notBefore{ 0 };
    notBefore.data = data;
    ASN1_TIME notAfter;
    notAfter.data = NULL;
    PKCS7Data p7Data;
    int result = PKCS7Data::CheckSignTimeInValidPeriod(signTime, &notBefore, &notAfter);
    EXPECT_TRUE(result < 0);
}

// pkcs7Data check sign time
HWTEST_F(Pkcs7DataTest, pkcs7_test019, testing::ext::TestSize.Level1)
{
    unsigned char data[5] = "hell";
    ASN1_TYPE* signTime = NULL;
    ASN1_TIME notBefore{ 0 };
    notBefore.data = data;
    ASN1_TIME notAfter;
    notAfter.data = data;
    PKCS7Data p7Data;
    int result = PKCS7Data::CheckSignTimeInValidPeriod(signTime, &notBefore, &notAfter);
    EXPECT_TRUE(result < 0);
}

// pkcs7Data check sign time
HWTEST_F(Pkcs7DataTest, pkcs7_test020, testing::ext::TestSize.Level1)
{
    unsigned char data[5] = "hell";
    ASN1_TYPE signTime;
    signTime.value.asn1_string = NULL;
    ASN1_TIME notBefore{ 0 };
    notBefore.data = data;
    ASN1_TIME notAfter;
    notAfter.data = data;
    PKCS7Data p7Data;
    int result = PKCS7Data::CheckSignTimeInValidPeriod(&signTime, &notBefore, &notAfter);
    EXPECT_TRUE(result < 0);
}

// pkcs7Data check sign time
HWTEST_F(Pkcs7DataTest, pkcs7_test021, testing::ext::TestSize.Level1)
{
    ASN1_STRING* tmp = ASN1_STRING_new();
    unsigned char data[5] = "hell";
    ASN1_TYPE signTime;
    signTime.value.asn1_string = tmp;
    signTime.value.asn1_string->data = NULL;
    ASN1_TIME notBefore{ 0 };
    notBefore.data = data;
    ASN1_TIME notAfter;
    notAfter.data = data;
    PKCS7Data p7Data;
    int result = PKCS7Data::CheckSignTimeInValidPeriod(&signTime, &notBefore, &notAfter);
    ASN1_STRING_free(tmp);
    EXPECT_TRUE(result < 0);
}

// pkcs7Data check sign time
HWTEST_F(Pkcs7DataTest, pkcs7_test022, testing::ext::TestSize.Level1)
{
    ASN1_TIME* tmp = NULL;
    ASN1_TYPE* signTime = NULL;
    ASN1_TIME* notBefore = NULL;
    ASN1_TIME* notAfter = NULL;
    time_t t1 = 365 * 24 * 3600;

    signTime = ASN1_TYPE_new();
    tmp = ASN1_TIME_new();
    notBefore = ASN1_TIME_new();
    notAfter = ASN1_TIME_new();
    time_t timeNow = time(NULL);
    ASN1_TIME_set(tmp, timeNow - t1);
    ASN1_TYPE_set(signTime, V_ASN1_UTCTIME, tmp);
    ASN1_TIME_set(notBefore, timeNow);
    ASN1_TIME_set(notAfter, timeNow + t1);
    int result = PKCS7Data::CheckSignTimeInValidPeriod(signTime, notBefore, notAfter);
    ASN1_TYPE_free(signTime);
    ASN1_TIME_free(notBefore);
    ASN1_TIME_free(notAfter);
    EXPECT_TRUE(result < 0);
}

// pkcs7Data check sign time
HWTEST_F(Pkcs7DataTest, pkcs7_test023, testing::ext::TestSize.Level1)
{
    ASN1_TIME* tmp = NULL;
    ASN1_TYPE* signTime = NULL;
    ASN1_TIME* notBefore = NULL;
    ASN1_TIME* notAfter = NULL;
    time_t t1 = 365 * 24 * 3600;

    signTime = ASN1_TYPE_new();
    tmp = ASN1_TIME_new();
    notBefore = ASN1_TIME_new();
    notAfter = ASN1_TIME_new();
    time_t timeNow = time(NULL);
    ASN1_TIME_set(tmp, timeNow + t1);
    ASN1_TYPE_set(signTime, V_ASN1_UTCTIME, tmp);
    ASN1_TIME_set(notBefore, timeNow - t1);
    ASN1_TIME_set(notAfter, timeNow);
    int result = PKCS7Data::CheckSignTimeInValidPeriod(signTime, notBefore, notAfter);
    ASN1_TYPE_free(signTime);
    ASN1_TIME_free(notBefore);
    ASN1_TIME_free(notAfter);
    EXPECT_TRUE(result < 0);
}
}
}