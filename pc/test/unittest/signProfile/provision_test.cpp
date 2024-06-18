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
#include "constant.h"
#include "profile_verify_utils.h"

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

static const std::string SIGN_PROFILE_CERT_PEM = "./signProfile/profile-release1-cert.pem";
static const std::string SIGN_PROFILE_REVERSE_PEM = "./signProfile/profile-release1-reverse.pem";
static const std::string SIGN_PROFILE_DOUBLE_CERT_PEM = "./signProfile/"
                                                        "profile-release1-invalid_cert_chain.pem";

//verify profile 使用的全局参数
static const std::string VERIFY_PROFILE_IN_FILE = "./signProfile/app1-profile1.p7b";
static const std::string VERIFY_PROFILE_OUT_FILE = "./signProfile/verify-result.json";
//sign app 使用全局参数
static const std::string SIGN_APP_MODE = "localSign";
static const std::string SIGN_APP_KEY_ALIAS = "oh-app1-key-v1";
static const std::string SIGN_APP_APP_CERT_FILE = "./signProfile/app-release1.pem";
static const std::string SIGN_APP_PROFILE_FILE = "./signProfile/app1-profile1.p7b";
static const std::string SIGN_APP_IN_FILE = "./signProfile/app1-unsigned.hap";
static const std::string SIGN_APP_SIGN_ALG = "SHA256withECDSA";
static const std::string SIGN_APP_KEY_STORE_FILE = "./signProfile/ohtest.p12";
static const std::string SIGN_APP_OUT_FILE = "./signProfile/app1-signed.hap";
//verify app 使用全局参数
static const std::string VERIFY_APP_CERT_FILE = "./signProfile/app-release1.pem";
static const std::string VERIFY_APP_PROFILE_FILE = "./signProfile/app1-profile1.p7b";
static const std::string VERIFY_APP_IN_FILE = "./signProfile/app1-signed.hap";

class ProvisionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp()override;
    void TearDown()override;
};
void ProvisionTest::SetUpTestCase(void)
{
}

void ProvisionTest::TearDownTestCase(void)
{
}

void ProvisionTest::SetUp()
{
}

void ProvisionTest::TearDown()
{
}

// GetCrls
HWTEST_F(ProvisionTest, provision_test001, testing::ext::TestSize.Level1)
{
    EVP_PKEY* pkey = NULL;
    STACK_OF(X509)* certs = NULL;
    std::shared_ptr<LocalSigner> signer = std::make_shared<LocalSigner>(pkey, certs);
    STACK_OF(X509_CRL)* crls = signer->GetCrls();
    EXPECT_TRUE(crls == NULL);
}

HWTEST_F(ProvisionTest, provision_test002, testing::ext::TestSize.Level1)
{
    std::string content = "signed content data";
    Options options;
    std::string mode = SIGN_PROFILE_MODE;
    std::string keyAlias = SIGN_PROFILE_KEY_ALIAS;
    std::string profileCertFile = SIGN_PROFILE_PROFILE_CERT_FILE;
    std::string signAlg = SIGN_PROFILE_SIGN_ALG;
    std::string keystoreFile = SIGN_PROFILE_KEY_STORE_FILE;
    std::string outFile = SIGN_PROFILE_OUT_FILE;
    std::string inFile = SIGN_PROFILE_IN_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = keyAlias;
    options[Options::MODE] = mode;
    options[Options::PROFILE_CERT_FILE] = profileCertFile;
    options[Options::SIGN_ALG] = signAlg;
    options[Options::KEY_STORE_FILE] = keystoreFile;
    options[Options::OUT_FILE] = outFile;
    options[Options::IN_FILE] = inFile;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    SignerFactory factory;
    std::shared_ptr<Signer> signer = factory.GetSigner(adapter);
    std::string signature1 = signer->GetSignature(content, "SHA384withECDSA");
    EXPECT_TRUE(signature1.size());
    std::string signature2 = signer->GetSignature(content, "SHA256withECDSA");
    EXPECT_TRUE(signature2.size());
    std::string signature3 = signer->GetSignature(content, "SHA999withECDSA");
    EXPECT_TRUE(signature3.empty());
    std::string signature4 = signer->GetSignature("", "SHA384withECDSA");
    EXPECT_FALSE(signature4.empty());
}

// provision
HWTEST_F(ProvisionTest, provision_test003, testing::ext::TestSize.Level1)
{
    SetRdDevice(false);
    std::string provision = R"({"acls":{"allowed-acls":["ac1","ac2"]},"bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"invalid debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0","baseapp-info":{"package-name":"package_name","package-cert":"package_cert"}})";
    ProfileInfo info;
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
    provision = R"({"acls":{"allowed-acls":["ac1","ac2"]},"bundle-info":{"app-feature":"hos_system_app","bundle-name":".*","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0","baseapp-info":{"package-name":"package_name","package-cert":"package_cert"}})";
    ProfileInfo info2;
    result = ParseProvision(provision, info2);
    EXPECT_TRUE(result == PROVISION_OK);
}

// provision info
HWTEST_F(ProvisionTest, provision_test004, testing::ext::TestSize.Level1)
{
}

// provision info not struct
HWTEST_F(ProvisionTest, provision_test005, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"(55.2)";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision info not struct
HWTEST_F(ProvisionTest, provision_test006, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"name": "feixing","age": 18}+)";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision info not struct
HWTEST_F(ProvisionTest, provision_test007, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"(55.2)";
    AppProvisionVerifyResult result = ParseProfile(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision info not struct
HWTEST_F(ProvisionTest, provision_test008, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"name": "feixing","age": 18}+)";
    AppProvisionVerifyResult result = ParseProfile(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision info not object
HWTEST_F(ProvisionTest, provision_test009, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"([88,99,42,11,22])";
    AppProvisionVerifyResult result = ParseProfile(provision, info);
    EXPECT_TRUE(result == PROVISION_OK);
}

// provision verify parse app dist type
HWTEST_F(ProvisionTest, provision_test010, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery","bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_TRUE(result == PROVISION_OK);
}

// provision verify parse version code not positive
HWTEST_F(ProvisionTest, provision_test011, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":0,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify parse version code not exist
HWTEST_F(ProvisionTest, provision_test012, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code_no":0,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify parse version code not number
HWTEST_F(ProvisionTest, provision_test013, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":"0","version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify app-privilege-capabilities contain not str
HWTEST_F(ProvisionTest, provision_test014, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-privilege-capabilities": [99,"88"],"bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_TRUE(result == PROVISION_OK);
}

// provision verify bundle-name is empty
HWTEST_F(ProvisionTest, provision_test015, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"bundle-info":{"app-feature":"hos_system_app","bundle-name":"","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify version-name is empty
HWTEST_F(ProvisionTest, provision_test016, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":""})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify uuid is empty
HWTEST_F(ProvisionTest, provision_test017, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":""})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify develop-id is empty
HWTEST_F(ProvisionTest, provision_test018, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify develop_certificate is empty
HWTEST_F(ProvisionTest, provision_test019, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":""},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify app_future is empty
HWTEST_F(ProvisionTest, provision_test020, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"bundle-info":{"app-feature":"","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision info profileBlockLength=0
HWTEST_F(ProvisionTest, provision_test021, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    ProfileInfo info2;
    info2.profileBlockLength = 0;
    info = info2;
}

// provision info profileBlockLength=0
HWTEST_F(ProvisionTest, provision_test022, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    ProfileInfo info2;
    info2.profileBlockLength = 0;
    info = info2;
}

// provision info profileBlock=NULL
HWTEST_F(ProvisionTest, provision_test023, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    ProfileInfo info2;
    info2.profileBlockLength = 5;
    info2.profileBlock = NULL;
    info = info2;
}

// provision info profileBlockLength=0
HWTEST_F(ProvisionTest, provision_test024, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    ProfileInfo info2;
    info2.profileBlockLength = 5;
    info2.profileBlock = NULL;
    info = info2;
}

// generateP7b  NULL signer
HWTEST_F(ProvisionTest, provision_test025, testing::ext::TestSize.Level1)
{
    Options options;
    char keyStorePwd[] = "123456";
    char invalidKeyPwd[] = "12345";
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::MODE] = SIGN_PROFILE_MODE;
    options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_PROFILE_CERT_FILE;
    options[Options::SIGN_ALG] = SIGN_PROFILE_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
    options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
    options[Options::KEY_RIGHTS] = invalidKeyPwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    std::string content = "json content";
    std::string ret;
    int result = ProfileSignTool::GenerateP7b(adapter, content, ret);
    EXPECT_FALSE(result == 0);
}

// generateP7b signprofile sigAlg failed
HWTEST_F(ProvisionTest, provision_test026, testing::ext::TestSize.Level1)
{
    Options options;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    std::string invalid_sigAlg = "SHA385withECDSA";
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::MODE] = SIGN_PROFILE_MODE;
    options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_PROFILE_CERT_FILE;
    options[Options::SIGN_ALG] = invalid_sigAlg;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
    options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    std::string content = "json content";
    std::string ret;
    int result = ProfileSignTool::GenerateP7b(adapter, content, ret);
    EXPECT_FALSE(result == 0);
}

// generateP7b signprofile success
HWTEST_F(ProvisionTest, provision_test027, testing::ext::TestSize.Level1)
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
    std::string content = "json content";
    std::string ret;
    int result = ProfileSignTool::GenerateP7b(adapter, content, ret);
    EXPECT_TRUE(result == 0);
}

// generateP7b signprofile success
HWTEST_F(ProvisionTest, provision_test028, testing::ext::TestSize.Level1)
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
    std::string content = "json content";
    std::string ret;
    int result = ProfileSignTool::SignProfile(content, signer, SIGN_PROFILE_SIGN_ALG, ret);
    EXPECT_TRUE(result == 0);
}

// generateP7b signprofile PROFILE_CERT_FILE only cert certNum<2 failed
HWTEST_F(ProvisionTest, provision_test029, testing::ext::TestSize.Level1)
{
    Options options;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::MODE] = SIGN_PROFILE_MODE;
    options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_CERT_PEM;
    options[Options::SIGN_ALG] = SIGN_PROFILE_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
    options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    std::string content = "json content";
    std::string ret;
    int result = ProfileSignTool::GenerateP7b(adapter, content, ret);
    EXPECT_FALSE(result == 0);
}

// generateP7b signprofile cert and certChain is same Verify failed
HWTEST_F(ProvisionTest, provision_test030, testing::ext::TestSize.Level1)
{
    Options options;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::MODE] = SIGN_PROFILE_MODE;
    options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_DOUBLE_CERT_PEM;
    options[Options::SIGN_ALG] = SIGN_PROFILE_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
    options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    std::string content = "json content";
    std::string ret;
    int result = ProfileSignTool::GenerateP7b(adapter, content, ret);
    EXPECT_FALSE(result == 0);
}

// crl NULL
HWTEST_F(ProvisionTest, provision_test031, testing::ext::TestSize.Level1)
{
    Options options;
    std::string mode = SIGN_PROFILE_MODE;
    std::string keyAlias = SIGN_PROFILE_KEY_ALIAS;
    std::string profileCertFile = SIGN_PROFILE_PROFILE_CERT_FILE;
    std::string signAlg = SIGN_PROFILE_SIGN_ALG;
    std::string keystoreFile = SIGN_PROFILE_KEY_STORE_FILE;
    std::string outFile = SIGN_PROFILE_OUT_FILE;
    std::string inFile = SIGN_PROFILE_IN_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = keyAlias;
    options[Options::MODE] = mode;
    options[Options::PROFILE_CERT_FILE] = profileCertFile;
    options[Options::SIGN_ALG] = signAlg;
    options[Options::KEY_STORE_FILE] = keystoreFile;
    options[Options::OUT_FILE] = outFile;
    options[Options::IN_FILE] = inFile;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    LocalizationAdapter adapter(&options);
    SignerFactory factory;
    std::shared_ptr<Signer> signer = factory.GetSigner(adapter);
    STACK_OF(X509_CRL)* crls = signer->GetCrls();
    EXPECT_TRUE(crls == NULL);
}

// pkey NULL
HWTEST_F(ProvisionTest, provision_test032, testing::ext::TestSize.Level1)
{
    Options options;
    std::string mode = SIGN_PROFILE_MODE;
    std::string keyAlias = SIGN_PROFILE_KEY_ALIAS;
    std::string profileCertFile = SIGN_PROFILE_PROFILE_CERT_FILE;
    std::string signAlg = SIGN_PROFILE_SIGN_ALG;
    std::string keystoreFile = SIGN_PROFILE_KEY_STORE_FILE;
    std::string outFile = SIGN_PROFILE_OUT_FILE;
    std::string inFile = SIGN_PROFILE_IN_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = keyAlias;
    options[Options::MODE] = mode;
    options[Options::PROFILE_CERT_FILE] = profileCertFile;
    options[Options::SIGN_ALG] = signAlg;
    options[Options::KEY_STORE_FILE] = keystoreFile;
    options[Options::OUT_FILE] = outFile;
    options[Options::IN_FILE] = inFile;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    EVP_PKEY* pkey = NULL;
    STACK_OF(X509)* certs = NULL;
    std::shared_ptr<Signer> signer = NULL;
    signer = std::make_shared<LocalSigner>(pkey, certs);
}

// certificates NULL
HWTEST_F(ProvisionTest, provision_test033, testing::ext::TestSize.Level1)
{
    Options options;
    std::string mode = SIGN_PROFILE_MODE;
    std::string keyAlias = SIGN_PROFILE_KEY_ALIAS;
    std::string profileCertFile = SIGN_PROFILE_PROFILE_CERT_FILE;
    std::string signAlg = SIGN_PROFILE_SIGN_ALG;
    std::string keystoreFile = SIGN_PROFILE_KEY_STORE_FILE;
    std::string outFile = SIGN_PROFILE_OUT_FILE;
    std::string inFile = SIGN_PROFILE_IN_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = keyAlias;
    options[Options::MODE] = mode;
    options[Options::PROFILE_CERT_FILE] = profileCertFile;
    options[Options::SIGN_ALG] = signAlg;
    options[Options::KEY_STORE_FILE] = keystoreFile;
    options[Options::OUT_FILE] = outFile;
    options[Options::IN_FILE] = inFile;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    EVP_PKEY* pkey = NULL;
    STACK_OF(X509)* certs = NULL;
    LocalizationAdapter adapter(&options);
    pkey = adapter.GetAliasKey(false);
    std::shared_ptr<Signer> signer = std::make_shared<LocalSigner>(pkey, certs);
}

// certificates num 0
HWTEST_F(ProvisionTest, provision_test034, testing::ext::TestSize.Level1)
{
    Options options;
    std::string mode = SIGN_PROFILE_MODE;
    std::string keyAlias = SIGN_PROFILE_KEY_ALIAS;
    std::string profileCertFile = SIGN_PROFILE_PROFILE_CERT_FILE;
    std::string signAlg = SIGN_PROFILE_SIGN_ALG;
    std::string keystoreFile = SIGN_PROFILE_KEY_STORE_FILE;
    std::string outFile = SIGN_PROFILE_OUT_FILE;
    std::string inFile = SIGN_PROFILE_IN_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = keyAlias;
    options[Options::MODE] = mode;
    options[Options::PROFILE_CERT_FILE] = profileCertFile;
    options[Options::SIGN_ALG] = signAlg;
    options[Options::KEY_STORE_FILE] = keystoreFile;
    options[Options::OUT_FILE] = outFile;
    options[Options::IN_FILE] = inFile;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    EVP_PKEY* pkey = NULL;
    STACK_OF(X509)* certs = sk_X509_new(NULL);
    LocalizationAdapter adapter(&options);
    pkey = adapter.GetAliasKey(false);
    std::shared_ptr<Signer> signer = std::make_shared<LocalSigner>(pkey, certs);
}

// get signature
HWTEST_F(ProvisionTest, provision_test035, testing::ext::TestSize.Level1)
{
    Options options;
    std::string mode = SIGN_PROFILE_MODE;
    std::string keyAlias = SIGN_PROFILE_KEY_ALIAS;
    std::string profileCertFile = SIGN_PROFILE_PROFILE_CERT_FILE;
    std::string signAlg = SIGN_PROFILE_SIGN_ALG;
    std::string keystoreFile = SIGN_PROFILE_KEY_STORE_FILE;
    std::string outFile = SIGN_PROFILE_OUT_FILE;
    std::string inFile = SIGN_PROFILE_IN_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_ALIAS] = keyAlias;
    options[Options::MODE] = mode;
    options[Options::PROFILE_CERT_FILE] = profileCertFile;
    options[Options::SIGN_ALG] = signAlg;
    options[Options::KEY_STORE_FILE] = keystoreFile;
    options[Options::OUT_FILE] = outFile;
    options[Options::IN_FILE] = inFile;
    options[Options::KEY_RIGHTS] = keypwd;
    options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

    EVP_PKEY* pkey = NULL;
    LocalizationAdapter adapter(&options);
    SignerFactory factory;
    std::shared_ptr<Signer> signer = factory.GetSigner(adapter);
    STACK_OF(X509)* certs = signer->GetCertificates();
    STACK_OF(X509)* certsDup = sk_X509_new(NULL);
    X509* cert = sk_X509_value(certs, 0);
    X509_up_ref(cert);
    sk_X509_push(certsDup, cert);
    std::shared_ptr<Signer> signer2 = std::make_shared<LocalSigner>(pkey, certsDup);
    std::string signature = signer2->GetSignature("content", "SHA384withECDSA");
}

// provision verify parse app dist type
HWTEST_F(ProvisionTest, provision_test036, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery",
"app-distribution-type": "app_gallery","bundle-info":{"app-feature":"hos_system_app",
"bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony",
"development-certificate":"-----BEGIN CERTIFICATE-----\n
MIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\n
A1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\n
eTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\n
MjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\n
A1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\n
eTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\n
odSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\n
UYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\n
o2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\n
BQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\n
AwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\n
QT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n
4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n
-----END CERTIFICATE-----\n"},
"debug-info":{"device-id-type":"udid",
"device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42",
"7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},
"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},
"type":"release","uuid":"fe686e1b-3770-4824-a938-961b140a7c98",
"validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify parse version code not positive
HWTEST_F(ProvisionTest, provision_test037, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery","bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"release","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":0,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify parse version code not exist
HWTEST_F(ProvisionTest, provision_test038, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery","bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"release","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code_no":0,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify parse version code not number
HWTEST_F(ProvisionTest, provision_test039, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery","bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"release","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":"0","version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify app-privilege-capabilities contain not str
HWTEST_F(ProvisionTest, provision_test040, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery","app-privilege-capabilities": [99,"88"],"bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"release","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify bundle-name is empty
HWTEST_F(ProvisionTest, provision_test041, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery","bundle-info":{"app-feature":"hos_system_app","bundle-name":"","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"release","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

HWTEST_F(ProvisionTest, provision_test042, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery","bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"release","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":""})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify uuid is empty
HWTEST_F(ProvisionTest, provision_test043, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery","bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"release","uuid":"","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":""})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify develop-id is empty
HWTEST_F(ProvisionTest, provision_test044, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery","bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"release","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify develop_certificate is empty
HWTEST_F(ProvisionTest, provision_test045, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery","bundle-info":{"app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":""},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

// provision verify app_future is empty
HWTEST_F(ProvisionTest, provision_test046, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery","bundle-info":{"app-feature":"","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"release","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":1,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_FALSE(result == PROVISION_OK);
}

HWTEST_F(ProvisionTest, provision_test047, testing::ext::TestSize.Level1)
{
    ProfileInfo info;
    std::string provision = R"({"app-distribution-type": "app_gallery","bundle-info":{"apl":"apl_","app-feature":"hos_system_app","bundle-name":"com.example.nativetemplatedemo","developer-id":"OpenHarmony","development-certificate":"-----BEGIN CERTIFICATE-----\nMIICXjCCAeOgAwIBAgIBATAKBggqhkjOPQQDAzBuMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEpMCcGA1UEAwwgQXBwbGljYXRpb24gU2lnbmF0dXJlIFNlcnZpY2UgQ0EwHhcN\nMjQwNDE1MDUzOTUyWhcNMjUwNDE1MDUzOTUyWjBaMQswCQYDVQQGEwJDTjEUMBIG\nA1UECgwLT3Blbkhhcm1vbnkxHjAcBgNVBAsMFU9wZW5IYXJtb255IENvbW11bml0\neTEVMBMGA1UEAwwMQXBwMSBSZWxlYXNlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nodSztdiucyVAo7VQnzHzBJsS9vQYa1vU1cP92F6fiJLazWtvEljNP1XoJldSZaN9\nUYGdAVHh2yrHzaJFEqHCSB3uQhlJgSbl9sT0lJ4hro1YvVx921/knMRlunz4eAGX\no2kwZzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEF\nBQcDAzAbBgNVHQ4EFEpzK6IntvQxLaKGX6xZQSiISBx+MBgGDCsGAQQBj1sCgngB\nAwQIMAYCAQEKAQAwCgYIKoZIzj0EAwMDaQAwZgIxAPboDdi9EhOiwAhO3N6vTRcK\nQT1K1TQq2vjvpC2231Dq4tLPeSzLz6ROq+Zv6IgBYgIxAJ9sZZUBoR2lgPHBzt01\n4uxt5nLfJj2XKa6Leb/JWDoosXjoVXoB47y699PtGetcFw==\n-----END CERTIFICATE-----\n"},"debug-info":{"device-id-type":"udid","device-ids":["69C7505BE341BDA5948C3C0CB44ABCD530296054159EFE0BD16A16CD0129CC42","7EED06506FCE6325EB2E2FAA019458B856AB10493A6718C7679A73F958732865"]},"issuer":"pki_internal","permissions":{"restricted-permissions":[""]},"type":"debug","uuid":"fe686e1b-3770-4824-a938-961b140a7c98","validity":{"not-after":1705127532,"not-before":1610519532},"version-code":3,"version-name":"1.0.0"})";
    AppProvisionVerifyResult result = ParseProvision(provision, info);
    EXPECT_TRUE(result == PROVISION_OK);
}

// pkcs7Context
HWTEST_F(ProvisionTest, provision_test048, testing::ext::TestSize.Level1)
{
    Pkcs7Context profilePkcs7Context;
    Pkcs7Context hapPkcs7Context;
    std::string profile = "hello,world";
    hapPkcs7Context.matchResult.matchState = MATCH_WITH_SIGN;
    hapPkcs7Context.matchResult.source = APP_GALLARY;
    ByteBuffer pkcs7ProfileBlock;
    pkcs7ProfileBlock.SetCapacity(5);
    pkcs7ProfileBlock.PutData("hello", 5);
    int result = ProfileVerifyUtils::ParseProfile(profilePkcs7Context, hapPkcs7Context, pkcs7ProfileBlock, profile);
    EXPECT_EQ(result, true);
}

// pkcs7Context
HWTEST_F(ProvisionTest, provision_test049, testing::ext::TestSize.Level1)
{
    Pkcs7Context profilePkcs7Context;
    Pkcs7Context hapPkcs7Context;
    int length = 5;
    std::string profile = "hello,world";
    hapPkcs7Context.matchResult.source = APP_GALLARY;
    ByteBuffer pkcs7ProfileBlock;
    pkcs7ProfileBlock.SetCapacity(length);
    pkcs7ProfileBlock.PutData("hello", length);
    int result = ProfileVerifyUtils::ParseProfile(profilePkcs7Context, hapPkcs7Context, pkcs7ProfileBlock, profile);
    EXPECT_EQ(result, false);
}

// pkcs7Context
HWTEST_F(ProvisionTest, provision_test050, testing::ext::TestSize.Level1)
{
    Pkcs7Context profilePkcs7Context;
    Pkcs7Context hapPkcs7Context;
    int length = 5;
    std::string profile = "hello,world";
    hapPkcs7Context.matchResult.matchState = MATCH_WITH_SIGN;
    ByteBuffer pkcs7ProfileBlock;
    pkcs7ProfileBlock.SetCapacity(length);
    pkcs7ProfileBlock.PutData("hello", length);
    int result = ProfileVerifyUtils::ParseProfile(profilePkcs7Context, hapPkcs7Context, pkcs7ProfileBlock, profile);
    EXPECT_EQ(result, false);
}

// pkcs7Context
HWTEST_F(ProvisionTest, provision_test051, testing::ext::TestSize.Level1)
{
    Pkcs7Context profilePkcs7Context;
    Pkcs7Context hapPkcs7Context;
    int length = 5;
    std::string profile = "hello,world";
    ByteBuffer pkcs7ProfileBlock;
    pkcs7ProfileBlock.SetCapacity(length);
    pkcs7ProfileBlock.PutData("hello", length);
    int result = ProfileVerifyUtils::ParseProfile(profilePkcs7Context, hapPkcs7Context, pkcs7ProfileBlock, profile);
    EXPECT_EQ(result, false);
}

// pkcs7Context verify certChain
HWTEST_F(ProvisionTest, provision_test052, testing::ext::TestSize.Level1)
{
    Pkcs7Context p7context;
    int result = ProfileVerifyUtils::VerifyProfile(p7context);
    EXPECT_EQ(result, false);
}

// pkcs7Context
HWTEST_F(ProvisionTest, provision_test053, testing::ext::TestSize.Level1)
{
    Pkcs7Context p7context;
    X509* cert = X509_new();
    std::vector<X509*> certChain;
    certChain.push_back(cert);
    p7context.certChains.push_back(certChain);
    int result = ProfileVerifyUtils::VerifyProfile(p7context);
    EXPECT_EQ(result, false);
}

// pkcs7Context
HWTEST_F(ProvisionTest, provision_test054, testing::ext::TestSize.Level1)
{
    std::string content;
    SignerConfig* config = NULL;
    std::string ret;
    std::shared_ptr<Pkcs7Generator> generator = std::make_shared<BCPkcs7Generator>();
    int result = generator->GenerateSignedData(content, config, ret);
    EXPECT_TRUE(result <= 0);
}

// bcpkcs7_generator
HWTEST_F(ProvisionTest, provision_test055, testing::ext::TestSize.Level1)
{
    std::string content = "hello,world";
    SignerConfig* config = NULL;
    std::string ret;
    std::shared_ptr<Pkcs7Generator> generator = std::make_shared<BCPkcs7Generator>();
    int result = generator->GenerateSignedData(content, config, ret);
    EXPECT_TRUE(result <= 0);
}

// bcpkcs7_generator
HWTEST_F(ProvisionTest, provision_test056, testing::ext::TestSize.Level1)
{
    Options options;
    options[Options::MODE] = SIGN_APP_MODE;
    options[Options::KEY_ALIAS] = SIGN_APP_KEY_ALIAS;
    options[Options::APP_CERT_FILE] = SIGN_APP_APP_CERT_FILE;
    options[Options::PROFILE_FILE] = SIGN_APP_PROFILE_FILE;
    options[Options::IN_FILE] = SIGN_APP_IN_FILE;
    options[Options::SIGN_ALG] = SIGN_APP_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = "";
    options[Options::OUT_FILE] = SIGN_APP_OUT_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyStorePwd;
    options[Options::KEY_STORE_RIGHTS] = keypwd;

    // config设置算法 signer
    SignerConfig config;
    config.SetOptions(&options);
    SignatureAlgorithmHelper algClass;
    std::vector<SignatureAlgorithmHelper> sigs;
    sigs.resize(1);
    sigs[0].id = SignatureAlgorithmId::ECDSA_WITH_SHA256;
    config.SetSignatureAlgorithms(sigs);

    std::string content = "digest content";
    std::string signedData;
    std::shared_ptr<Pkcs7Generator> pkcs7Generator = std::make_shared<BCPkcs7Generator>();
    int result = pkcs7Generator->GenerateSignedData(content, &config, signedData);
    EXPECT_TRUE(result < 0);
}

// bcpkcs7_generator
HWTEST_F(ProvisionTest, provision_test057, testing::ext::TestSize.Level1)
{
    Options options;
    options[Options::MODE] = SIGN_APP_MODE;
    options[Options::KEY_ALIAS] = SIGN_APP_KEY_ALIAS;
    options[Options::APP_CERT_FILE] = SIGN_APP_APP_CERT_FILE;
    options[Options::PROFILE_FILE] = SIGN_APP_PROFILE_FILE;
    options[Options::IN_FILE] = SIGN_APP_IN_FILE;
    options[Options::SIGN_ALG] = SIGN_APP_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_APP_OUT_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyStorePwd;
    options[Options::KEY_STORE_RIGHTS] = keypwd;

    // config设置算法 signer
    SignerConfig config;
    config.SetOptions(&options);
    SignatureAlgorithmHelper algClass;
    std::vector<SignatureAlgorithmHelper> sigs;
    sigs.resize(1);
    sigs[0].id = SignatureAlgorithmId::DSA_WITH_SHA512;
    config.SetSignatureAlgorithms(sigs);

    std::string content = "digest content";
    std::string signedData;
    std::shared_ptr<Pkcs7Generator> pkcs7Generator = std::make_shared<BCPkcs7Generator>();
    int result = pkcs7Generator->GenerateSignedData(content, &config, signedData);
    EXPECT_TRUE(result < 0);
}

// bcpkcs7_generator
HWTEST_F(ProvisionTest, provision_test058, testing::ext::TestSize.Level1)
{
    Options options;
    options[Options::MODE] = SIGN_APP_MODE;
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::APP_CERT_FILE] = SIGN_PROFILE_DOUBLE_CERT_PEM;
    options[Options::PROFILE_FILE] = SIGN_APP_PROFILE_FILE;
    options[Options::IN_FILE] = SIGN_APP_IN_FILE;
    options[Options::SIGN_ALG] = SIGN_APP_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_APP_OUT_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyStorePwd;
    options[Options::KEY_STORE_RIGHTS] = keypwd;

    // config设置算法 signer
    SignerConfig config;
    config.SetOptions(&options);
    SignatureAlgorithmHelper algClass;
    std::vector<SignatureAlgorithmHelper> sigs;
    sigs.resize(1);
    sigs[0].id = SignatureAlgorithmId::ECDSA_WITH_SHA256;
    config.SetSignatureAlgorithms(sigs);

    std::string content = "digest content";
    std::string signedData;
    std::shared_ptr<Pkcs7Generator> pkcs7Generator = std::make_shared<BCPkcs7Generator>();
    int result = pkcs7Generator->GenerateSignedData(content, &config, signedData);
    EXPECT_TRUE(result < 0);
}

// sigAlg failed
HWTEST_F(ProvisionTest, provision_test059, testing::ext::TestSize.Level1)
{
    Options options;
    options[Options::MODE] = SIGN_APP_MODE;
    options[Options::KEY_ALIAS] = SIGN_APP_KEY_ALIAS;
    options[Options::APP_CERT_FILE] = SIGN_APP_APP_CERT_FILE;
    options[Options::PROFILE_FILE] = SIGN_APP_PROFILE_FILE;
    options[Options::IN_FILE] = SIGN_APP_IN_FILE;
    options[Options::SIGN_ALG] = SIGN_APP_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_APP_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_APP_OUT_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyStorePwd;
    options[Options::KEY_STORE_RIGHTS] = keypwd;

    // config设置算法 signer
    SignerConfig config;
    config.SetOptions(&options);
    SignatureAlgorithmHelper algClass;
    std::vector<SignatureAlgorithmHelper> sigs;
    sigs.resize(1);
    sigs[0].id = SignatureAlgorithmId::ECDSA_WITH_SHA512;
    config.SetSignatureAlgorithms(sigs);

    std::string content = "digest content";
    std::string signedData;
    std::shared_ptr<BCSignedDataGenerator> signedDataGenerator =
        std::make_shared<BCSignedDataGenerator>();
    signedDataGenerator->SetOwnerId(OWNERID_OID);
    int result = signedDataGenerator->GenerateSignedData(content, &config, signedData);
    EXPECT_TRUE(result < 0);
}

// bcsigneddata verify failed
HWTEST_F(ProvisionTest, provision_test060, testing::ext::TestSize.Level1)
{
    Options options;
    options[Options::MODE] = SIGN_APP_MODE;
    options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
    options[Options::APP_CERT_FILE] = SIGN_PROFILE_DOUBLE_CERT_PEM;
    options[Options::PROFILE_FILE] = SIGN_APP_PROFILE_FILE;
    options[Options::IN_FILE] = SIGN_APP_IN_FILE;
    options[Options::SIGN_ALG] = SIGN_APP_SIGN_ALG;
    options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
    options[Options::OUT_FILE] = SIGN_APP_OUT_FILE;
    char keyStorePwd[] = "123456";
    char keypwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyStorePwd;
    options[Options::KEY_STORE_RIGHTS] = keypwd;

    // config设置算法 signer
    SignerConfig config;
    config.SetOptions(&options);
    SignatureAlgorithmHelper algClass;
    std::vector<SignatureAlgorithmHelper> sigs;
    sigs.resize(1);
    sigs[0].id = SignatureAlgorithmId::ECDSA_WITH_SHA256;
    config.SetSignatureAlgorithms(sigs);

    std::string content = "digest content";
    std::string signedData;
    std::shared_ptr<BCSignedDataGenerator> signedDataGenerator =
        std::make_shared<BCSignedDataGenerator>();
    signedDataGenerator->SetOwnerId("ownerID str");
    int result = signedDataGenerator->GenerateSignedData(content, &config, signedData);
    EXPECT_TRUE(result < 0);
}

// // verify cert chain failed
// HWTEST_F(ProvisionTest, test061, testing::ext::TestSize.Level1)
// {
//     std::string content = "signed content data";
//     Options options;
//     char keyStorePwd[] = "123456";
//     char keypwd[] = "123456";
//     options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
//     options[Options::MODE] = SIGN_PROFILE_MODE;
//     options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_PROFILE_CERT_FILE;
//     options[Options::SIGN_ALG] = SIGN_PROFILE_SIGN_ALG;
//     options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
//     options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
//     options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
//     options[Options::KEY_RIGHTS] = keypwd;
//     options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

//     LocalizationAdapter adapter(&options);
//     SignerFactory factory;
//     std::shared_ptr<Signer> signer = factory.GetSigner(adapter);
//     PKCS7Data p7;
//     std::string p7b;
//     PKCS7* pkcs7 = NULL;
//     int result = p7.Sign(content, signer, "SHA384withECDSA", p7b);
//     EXPECT_EQ(result, 0);
//     const unsigned char* p = reinterpret_cast<const unsigned char*>(p7b.data());
//     pkcs7=d2i_PKCS7(NULL, &p, static_cast<long>(p7b.size()));
//     STACK_OF(X509)*certs=pkcs7->d.sign->cert;
//     int num = 1;
//     while (sk_X509_num(certs) > num) {
//         X509*cert=sk_X509_delete(certs, sk_X509_num(certs) - 1);
//         X509_free(cert);
//     }
//     sk_X509_push(certs, sk_X509_value(certs,0));
//     X509_up_ref(sk_X509_value(certs, 0));
//     unsigned char* out = NULL;
//     int len = 0;
//     len=i2d_PKCS7(pkcs7, &out);
//     p7b.assign(out, out+len);
//     result=p7.Parse(p7b);
//     EXPECT_EQ(result, 0);
//     result=p7.Verify();
//     PKCS7_free(pkcs7);
//     EXPECT_TRUE(result < 0);
// }

// // verify cert chain failed
// HWTEST_F(ProvisionTest, test062, testing::ext::TestSize.Level1)
// {
//     std::string content = "signed content data";
//     Options options;
//     char keyStorePwd[] = "123456";
//     char keypwd[] = "123456";
//     options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
//     options[Options::MODE] = SIGN_PROFILE_MODE;
//     options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_PROFILE_CERT_FILE;
//     options[Options::SIGN_ALG] = SIGN_PROFILE_SIGN_ALG;
//     options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
//     options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
//     options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
//     options[Options::KEY_RIGHTS] = keypwd;
//     options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

//     LocalizationAdapter adapter(&options);
//     SignerFactory factory;
//     std::shared_ptr<Signer> signer = factory.GetSigner(adapter);
//     PKCS7Data p7;
//     std::string p7b;
//     PKCS7* pkcs7 = NULL;
//     int result = p7.Sign(content, signer, "SHA384withECDSA", p7b);
//     EXPECT_EQ(result, 0);
//     const unsigned char* p = reinterpret_cast<const unsigned char*>(p7b.data());
//     pkcs7 = d2i_PKCS7(NULL, &p, static_cast<long>(p7b.size()));
//     STACK_OF(X509)* certs = pkcs7->d.sign->cert;
//     sk_X509_delete(certs, 2);
//     unsigned char* out = NULL;
//     int len = 0;
//     len = i2d_PKCS7(pkcs7, &out);
//     p7b.assign(out, out + len);
//     result = p7.Parse(p7b);
//     EXPECT_EQ(result, 0);
//     result = p7.Verify();
//     PKCS7_free(pkcs7);
//     EXPECT_TRUE(result < 0);
// }

// // verify cert chain failed
// HWTEST_F(ProvisionTest, test063, testing::ext::TestSize.Level1)
// {
//     std::string content = "signed content data";
//     Options options;
//     char keyStorePwd[] = "123456";
//     char keypwd[] = "123456";
//     options[Options::KEY_ALIAS] = SIGN_PROFILE_KEY_ALIAS;
//     options[Options::MODE] = SIGN_PROFILE_MODE;
//     options[Options::PROFILE_CERT_FILE] = SIGN_PROFILE_PROFILE_CERT_FILE;
//     options[Options::SIGN_ALG] = SIGN_PROFILE_SIGN_ALG;
//     options[Options::KEY_STORE_FILE] = SIGN_PROFILE_KEY_STORE_FILE;
//     options[Options::OUT_FILE] = SIGN_PROFILE_OUT_FILE;
//     options[Options::IN_FILE] = SIGN_PROFILE_IN_FILE;
//     options[Options::KEY_RIGHTS] = keypwd;
//     options[Options::KEY_STORE_RIGHTS] = keyStorePwd;

//     LocalizationAdapter adapter(&options);
//     SignerFactory factory;
//     std::shared_ptr<Signer> signer = factory.GetSigner(adapter);
//     PKCS7Data p7;
//     std::string p7b;
//     PKCS7* pkcs7 = NULL;
//     int result = p7.Sign(content, signer, "SHA384withECDSA", p7b);
//     EXPECT_EQ(result, 0);
//     const unsigned char* p = reinterpret_cast<const unsigned char*>(p7b.data());
//     pkcs7 = d2i_PKCS7(NULL, &p, static_cast<long>(p7b.size()));
//     STACK_OF(X509)* certs = pkcs7->d.sign->cert;
//     sk_X509_delete(certs, 2);
//     sk_X509_push(certs, sk_X509_value(certs, 1));
//     X509_up_ref(sk_X509_value(certs, 1));
//     PKCS7Data::PrintCertChainSub(certs);
//     unsigned char* out = NULL;
//     int len = 0;
//     len = i2d_PKCS7(pkcs7, &out);
//     p7b.assign(out, out + len);
//     result = p7.Parse(p7b);
//     PKCS7Data::PrintCertChainSub(certs);
//     EXPECT_EQ(result, 0);
//     result = p7.Verify();
//     PKCS7_free(pkcs7);
//     EXPECT_TRUE(result < 0);
// }
}
}