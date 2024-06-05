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

#include "hap_verify_v2_test.h"
#include <string>
#include <gtest/gtest.h>
#include "provision_info.h"
#include "hap_verify_v2.h"
#include "test_hap_file_data.h"

using namespace testing::ext;
using namespace OHOS::SignatureTools;

namespace {
    const std::string ERROR_CERTIFICATE = "errorCertificate";
    const std::string TEST_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n\
MIICMzCCAbegAwIBAgIEaOC/zDAMBggqhkjOPQQDAwUAMGMxCzAJBgNVBAYTAkNO\n\
MRQwEgYDVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVh\n\
bTEjMCEGA1UEAxMaT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gQ0EwHhcNMjEwMjAy\n\
MTIxOTMxWhcNNDkxMjMxMTIxOTMxWjBoMQswCQYDVQQGEwJDTjEUMBIGA1UEChML\n\
T3Blbkhhcm1vbnkxGTAXBgNVBAsTEE9wZW5IYXJtb255IFRlYW0xKDAmBgNVBAMT\n\
H09wZW5IYXJtb255IEFwcGxpY2F0aW9uIFJlbGVhc2UwWTATBgcqhkjOPQIBBggq\n\
hkjOPQMBBwNCAATbYOCQQpW5fdkYHN45v0X3AHax12jPBdEDosFRIZ1eXmxOYzSG\n\
JwMfsHhUU90E8lI0TXYZnNmgM1sovubeQqATo1IwUDAfBgNVHSMEGDAWgBTbhrci\n\
FtULoUu33SV7ufEFfaItRzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFPtxruhl\n\
cRBQsJdwcZqLu9oNUVgaMAwGCCqGSM49BAMDBQADaAAwZQIxAJta0PQ2p4DIu/ps\n\
LMdLCDgQ5UH1l0B4PGhBlMgdi2zf8nk9spazEQI/0XNwpft8QAIwHSuA2WelVi/o\n\
zAlF08DnbJrOOtOnQq5wHOPlDYB4OtUzOYJk9scotrEnJxJzGsh/\n\
-----END CERTIFICATE-----\n";

    class HapVerifyV2Test : public testing::Test {
    public:
        static void SetUpTestCase(void);

        static void TearDownTestCase(void);

        void SetUp();

        void TearDown();
    };

    void HapVerifyV2Test::SetUpTestCase(void)
    {
    }

    void HapVerifyV2Test::TearDownTestCase(void)
    {
    }

    void HapVerifyV2Test::SetUp()
    {
    }

    void HapVerifyV2Test::TearDown()
    {
    }

    /**
     * @tc.name: Test CheckFilePath function
     * @tc.desc: The static function test whether input is a valid filepath;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyV2Test, CheckFilePathTest001, TestSize.Level1)
    {
        /*
         * @tc.steps: step1. input an too long filepath.
         * @tc.expected: step1. the return will be false.
         */
        HapVerifyV2 v2;
        std::string filePath = HAP_FILE_ECC_SIGN_BASE64;
        std::string standardFilePath;
        ASSERT_FALSE(v2.CheckFilePath(filePath, standardFilePath));
    }

    /**
     * @tc.name: Test GenerateAppId function
     * @tc.desc: The static function will return whether generate appid successfully;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyV2Test, GenerateAppIdTest001, TestSize.Level1)
    {
        /*
         * @tc.steps: step1. input a null ProvisionInfo.
         * @tc.expected: step1. the return will be false.
         */
        HapVerifyV2 v2;
        ProvisionInfo provisionInfo;
        ASSERT_FALSE(v2.GenerateAppId(provisionInfo));
    }

    /**
     * @tc.name: Test GenerateFingerprint function
     * @tc.desc: The static function will return whether generate fingerprint successfully;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyV2Test, GenerateFingerprintTest001, TestSize.Level1)
    {
        /*
         * @tc.steps: step1. input a null ProvisionInfo.
         * @tc.expected: step1. the return will be false.
         */
        HapVerifyV2 v2;
        ProvisionInfo provisionInfo;
        ASSERT_FALSE(v2.GenerateFingerprint(provisionInfo));
    }

    /**
     * @tc.name: Test GenerateFingerprint function
     * @tc.desc: The static function will return whether generate fingerprint successfully;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyV2Test, GenerateFingerprintTest002, TestSize.Level1)
    {
        /*
         * @tc.steps: step1. input ProvisionInfo with error distributionCertificate.
         * @tc.expected: step1. the return will be false.
         */
        HapVerifyV2 v2;
        ProvisionInfo provisionInfo;
        provisionInfo.bundleInfo.distributionCertificate = ERROR_CERTIFICATE;
        ASSERT_FALSE(v2.GenerateFingerprint(provisionInfo));
    }

    /**
     * @tc.name: Test GenerateFingerprint function
     * @tc.desc: The static function will return whether generate fingerprint successfully;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyV2Test, GenerateFingerprintTest003, TestSize.Level1)
    {
        /*
         * @tc.steps: step1. input ProvisionInfo with error distributionCertificate.
         * @tc.expected: step1. the return will be false.
         */
        HapVerifyV2 v2;
        ProvisionInfo provisionInfo;
        provisionInfo.bundleInfo.developmentCertificate = ERROR_CERTIFICATE;
        ASSERT_FALSE(v2.GenerateFingerprint(provisionInfo));
    }

    /**
     * @tc.name: Test GenerateFingerprint function
     * @tc.desc: The static function will return whether generate fingerprint successfully;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyV2Test, GenerateFingerprintTest004, TestSize.Level1)
    {
        /*
         * @tc.steps: step1. input ProvisionInfo with error distributionCertificate.
         * @tc.expected: step1. the return will be false.
         */
        HapVerifyV2 v2;
        ProvisionInfo provisionInfo;
        provisionInfo.bundleInfo.distributionCertificate = TEST_CERTIFICATE;
        ASSERT_TRUE(v2.GenerateFingerprint(provisionInfo));
    }

    /**
     * @tc.name: Test GenerateFingerprint function
     * @tc.desc: The static function will return whether generate fingerprint successfully;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyV2Test, GenerateFingerprintTest005, TestSize.Level1)
    {
        /*
         * @tc.steps: step1. input ProvisionInfo with correct distributionCertificate.
         * @tc.expected: step1. the return will be true.
         */
        HapVerifyV2 v2;
        ProvisionInfo provisionInfo;
        provisionInfo.bundleInfo.developmentCertificate = TEST_CERTIFICATE;
        ASSERT_TRUE(v2.GenerateFingerprint(provisionInfo));
    }

    /**
     * @tc.name: Test VerifyProfileInfo function
     * @tc.desc: The static function will return result of verify profile info;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyV2Test, VerifyProfileInfoTest001, TestSize.Level1)
    {
        /*
         * @tc.steps: step1. profile match with debug and profile type is release.
         * @tc.expected: step1. the return will be false.
         */
        HapVerifyV2 v2;
        Pkcs7Context pkcs7Context;
        Pkcs7Context profileContext;
        ProvisionInfo provisionInfo;
        profileContext.matchResult.matchState = MATCH_WITH_PROFILE_DEBUG;
        provisionInfo.type = ProvisionType::RELEASE;
        ASSERT_FALSE(v2.VerifyProfileInfo(pkcs7Context, profileContext, provisionInfo));
    }

    /**
     * @tc.name: Test ParseAndVerifyProfileIfNeed function
     * @tc.desc: The static function will return result of ParseAndVerifyProfileIfNeed;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyV2Test, ParseAndVerifyProfileIfNeedTest001, TestSize.Level1)
    {
        /*
         * @tc.steps: step1. input a null profile.
         * @tc.expected: step1. the return will be false.
         */
        HapVerifyV2 v2;
        std::string profile;
        ProvisionInfo provisionInfo;
        ASSERT_FALSE(v2.ParseAndVerifyProfileIfNeed(profile, provisionInfo, false));
        /*
         * @tc.steps: step1. input no need parse and verify profile.
         * @tc.expected: step1. the return will be true.
         */
        ASSERT_TRUE(v2.ParseAndVerifyProfileIfNeed(profile, provisionInfo, true));
    }

    /**
     * @tc.name: Test GetDigestAndAlgorithm function
     * @tc.desc: The static function will return result of GetDigestAndAlgorithm;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyV2Test, GetDigestAndAlgorithmTest001, TestSize.Level1)
    {
        /*
         * @tc.steps: step1. input an error pkcs7 content.
         * @tc.expected: step1. the return will be false.
         */
        HapVerifyV2 v2;
        Pkcs7Context digest;
        digest.content.SetCapacity(TEST_FILE_BLOCK_LENGTH);
        ASSERT_FALSE(v2.GetDigestAndAlgorithm(digest));
    }
}
