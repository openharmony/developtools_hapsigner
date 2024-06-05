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

#include "hap_verify_test.h"

#include <fstream>
#include <string>

#include <gtest/gtest.h>

#include "hap_verify.h"
#include "hap_verify_result.h"

#include "hap_cert_verify_openssl_utils_test.h"
#include "test_const.h"
#include "test_hap_file_data.h"
#include "file_utils.h"
#include "random_access_file.h"
#include "signature_tools_log.h"
#include "hap_verify_v2.h"
#include "signing_block_utils.h"
#include "hap_verify_result.h"
#include "openssl/pem.h"
#include "options.h"

using namespace testing::ext;
using namespace OHOS::SignatureTools;

namespace {
    class HapVerifyTest : public testing::Test {
    public:
        static void SetUpTestCase(void);

        static void TearDownTestCase(void);

        void SetUp();

        void TearDown();
    };

    void HapVerifyTest::SetUpTestCase(void)
    {
    }

    void HapVerifyTest::TearDownTestCase(void)
    {
    }

    void HapVerifyTest::SetUp()
    {
    }

    void HapVerifyTest::TearDown()
    {
    }

    /**
     * @tc.name: HapVerifyTest.HapVerify001
     * @tc.desc: The static function will return verify result;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyTest, HapVerify001, TestSize.Level0)
    {
        /*
         * @tc.steps: step1. input a invalid path to function of HapVerify.
         * @tc.expected: step1. the return will be FILE_PATH_INVALID.
         */
        OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
        Options options;
        options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.pem";
        options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

        std::string errorFile = "./hapVerify/signed_test.app";
        int32_t resultCode = HapVerify(errorFile, hapVerifyResult, &options);
        OHOS::SignatureTools::HapVerifyResultCode targetResult = OHOS::SignatureTools::FILE_PATH_INVALID;
        ASSERT_TRUE(resultCode == targetResult);
        std::ofstream appFile;
        appFile.open(errorFile.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
        ASSERT_TRUE(appFile.is_open());
        appFile.close();
        resultCode = HapVerify(errorFile, hapVerifyResult, &options);
        ASSERT_TRUE(resultCode == targetResult);
        /*
         * @tc.steps: step2. create a hapfile and run HapVerify.
         * @tc.expected: step2. the return will be SIGNATURE_NOT_FOUND.
         */
        std::string rightFile = "./hapVerify/signed.hap";
        std::ofstream hapFile;
        hapFile.open(rightFile.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
        ASSERT_TRUE(hapFile.is_open());
        hapFile.seekp(0, std::ios_base::beg);
        hapFile.write(MINIHAPFILE, TEST_MINI_HAP_FILE_LENGTH);
        hapFile.close();
        resultCode = HapVerify(rightFile, hapVerifyResult, &options);
        ASSERT_TRUE(resultCode == OHOS::SignatureTools::SIGNATURE_NOT_FOUND);

        /*
         * @tc.steps: step3. create an error hapfile and run HapVerify.
         * @tc.expected: step3. the return will be SIGNATURE_NOT_FOUND.
         */
        std::string rightFile1 = "./hapVerify/signed1.hap";
        std::ofstream hapFile1;
        hapFile1.open(rightFile1.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
        ASSERT_TRUE(hapFile1.is_open());
        hapFile1.seekp(0, std::ios_base::beg);
        hapFile1.write(MINIHAPFILE, sizeof(MINIHAPFILE));
        hapFile1.seekp(TEST_MINI_HAP_FILE_LENGTH - sizeof(short), std::ios_base::beg);
        hapFile1.close();
        resultCode = HapVerify(rightFile1, hapVerifyResult, &options);
        ASSERT_TRUE(resultCode == OHOS::SignatureTools::SIGNATURE_NOT_FOUND);

        /*
         * @tc.steps: step4. use an empty file to run HapVerify.
         * @tc.expected: step4. the return will be SIGNATURE_NOT_FOUND.
         */
        std::string invalidFile = "./hapVerify/signed2.hap";
        std::ofstream hapFile2;
        hapFile2.open(invalidFile.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
        ASSERT_TRUE(hapFile2.is_open());
        hapFile2.close();
        resultCode = HapVerify(invalidFile, hapVerifyResult, &options);
        ASSERT_TRUE(resultCode == OHOS::SignatureTools::SIGNATURE_NOT_FOUND);
    }

    /**
     * @tc.name: HapVerifyTest.HapVerifyOsApp001
     * @tc.desc: The static function will return verify result of signed file;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyTest, HapVerifyOsApp001, TestSize.Level0)
    {
        /*
         * @tc.steps: step1. input a signed file to verify.
         * @tc.expected: step1. the return will be VERIFY_SUCCESS.
         */

        std::string filePath = "./hapVerify/phone-default-signed.hap";
        Options options;
        options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.pem";
        options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";
        OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
        int32_t ret = HapVerify(filePath, hapVerifyResult, &options);
        ASSERT_EQ(ret, OHOS::SignatureTools::VERIFY_SUCCESS);
    }

    /**
     * @tc.name: HapVerifyTest.HapVerify002
     * @tc.desc: The static function will return verify result of signed file;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyTest, HapVerify002, TestSize.Level0)
    {
        std::string filePath = "./hapVerify/phone-default-signed.hap";
        std::string errorfilePath = "./hapVerify/phone-default-signed_error.hap";
        Options options;
        options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.pem";
        options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

        OHOS::SignatureTools::ByteBuffer byteBuffer;
        std::ifstream hapFile;
        hapFile.open(filePath, std::ifstream::binary);
        ASSERT_TRUE(hapFile.is_open());
        std::stringstream hapFileStr;
        hapFileStr << hapFile.rdbuf();
        size_t strSize = hapFileStr.str().size();
        byteBuffer.SetCapacity(strSize);
        byteBuffer.PutData(hapFileStr.str().c_str(), hapFileStr.str().size());
        hapFile.close();
        /*
            * @tc.steps: step1. input a signed file to verify.
            * @tc.expected: step1. the return will be VERIFY_SUCCESS.
            */
        OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
        ASSERT_TRUE(HapVerify(filePath, hapVerifyResult, &options) == OHOS::SignatureTools::VERIFY_SUCCESS);
        // /*
        //     * @tc.steps: step2. check verify result.
        //     * @tc.expected: step2. cert version is 1, certChains Len is 3.
        //     */
        OHOS::SignatureTools::ProvisionInfo profile = hapVerifyResult.GetProvisionInfo();
        ASSERT_EQ(profile.type, OHOS::SignatureTools::ProvisionType::DEBUG);
        std::vector<std::string> publicKeys = hapVerifyResult.GetPublicKey();
        ASSERT_TRUE(static_cast<int>(publicKeys.size()) == TEST_CERT_CHAIN_LEN);
        std::vector<std::string> signatures = hapVerifyResult.GetSignature();
        ASSERT_TRUE(static_cast<int>(signatures.size()) == TEST_CERT_CHAIN_LEN);
        /*
            * @tc.steps: step3. change comment data.
            * @tc.expected: step3. the return will be VERIFY_INTEGRITY_FAIL.
            */
        OHOS::SignatureTools::ByteBuffer errorCommentFile = byteBuffer;
        char tmp = TEST_HAPBYTEBUFFER_CHAR_DATA;
        errorCommentFile.PutByte(0, tmp);
        std::ofstream errorFile;
        errorFile.open(errorfilePath.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
        ASSERT_TRUE(errorFile.is_open());
        errorFile.seekp(0, std::ios_base::beg);
        errorFile.write(errorCommentFile.GetBufferPtr(), errorCommentFile.GetCapacity());
        errorFile.close();
        OHOS::SignatureTools::HapVerifyResult verifyRet;
        ASSERT_EQ(HapVerify(errorfilePath, verifyRet, &options), OHOS::SignatureTools::VERIFY_CODE_SIGN_FAIL);
        /*
            * @tc.steps: step4. change profile pkcs7 data.
            * @tc.expected: step4. the return will be APP_SOURCE_NOT_TRUSTED.
            */
        errorCommentFile.PutByte(TEST_PFOFILE_PKCS7_DATA_INDEX, tmp);
        errorFile.open(errorfilePath.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
        ASSERT_TRUE(errorFile.is_open());
        errorFile.seekp(0, std::ios_base::beg);
        errorFile.write(errorCommentFile.GetBufferPtr(), errorCommentFile.GetCapacity());
        errorFile.close();
        ASSERT_EQ(HapVerify(errorfilePath, verifyRet, &options), OHOS::SignatureTools::VERIFY_CODE_SIGN_FAIL);
        /*
            * @tc.steps: step5. change app pkcs7 data.
            * @tc.expected: step5. the return will be VERIFY_APP_PKCS7_FAIL.
            */
        errorCommentFile.PutByte(TEST_APP_PKCS7_DATA_INDEX, tmp);
        errorFile.open(errorfilePath.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
        ASSERT_TRUE(errorFile.is_open());
        errorFile.seekp(0, std::ios_base::beg);
        errorFile.write(errorCommentFile.GetBufferPtr(), errorCommentFile.GetCapacity());
        errorFile.close();
        ASSERT_EQ(HapVerify(errorfilePath, verifyRet, &options), OHOS::SignatureTools::VERIFY_CODE_SIGN_FAIL);
    }

    /**
     * @tc.name: HapVerifyTest.HapVerify003
     * @tc.desc: The static function will return verify result of signed file;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyTest, HapVerify003, TestSize.Level0)
    {
        std::string fileContent = HAP_FILE_ECC_SIGN_BASE64;
        std::string filePath = "./hapVerify/signed_ecc.hap";
        std::string outProfile = "./hapVerify/profile.p7b";
        OHOS::SignatureTools::ByteBuffer hapFileEccSign;
        ASSERT_TRUE(Base64StringDecode(fileContent, hapFileEccSign));
        std::ofstream hapFile;
        hapFile.open(filePath.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
        ASSERT_TRUE(hapFile.is_open());
        hapFile.seekp(0, std::ios_base::beg);
        hapFile.write(hapFileEccSign.GetBufferPtr(), hapFileEccSign.GetCapacity());
        hapFile.close();
        HapVerifyResult hapVerifyResult;
        ASSERT_TRUE(ParseHapProfile(filePath, hapVerifyResult, outProfile) == VERIFY_SUCCESS);

        SignatureInfo hapSignInfo;
        ASSERT_TRUE(ParseHapSignatureInfo(filePath, hapSignInfo) == VERIFY_SUCCESS);
        ProvisionInfo profile = hapVerifyResult.GetProvisionInfo();
        ASSERT_EQ(profile.type, ProvisionType::RELEASE);
        ASSERT_EQ(profile.fingerprint, TEST_FINGERPRINT);
        ASSERT_EQ(profile.versionCode, TEST_VERSION_CODE);
        ASSERT_EQ(profile.versionName, TEST_VERSION_NAME);
        ASSERT_EQ(profile.distributionType, AppDistType::OS_INTEGRATION);
    }
    /**
     * @tc.name: HapVerifyTest.HapVerify004
     * @tc.desc: The static function will return verify result of signed file;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyTest, HapVerify004, TestSize.Level0)
    {
        MatchingStates matchState = MATCH_WITH_PROFILE_DEBUG;
        ProvisionType type = DEBUG;
        HapVerifyV2 verify;
        bool ret = verify.CheckProfileSignatureIsRight(matchState, type);
        EXPECT_EQ(ret, true);
    }
    /**
    * @tc.name: HapVerifyTest.HapVerify005
    * @tc.desc: The static function will return verify result of signed file;
    * @tc.type: FUNC
    */
    HWTEST_F(HapVerifyTest, HapVerify005, TestSize.Level0)
    {
        MatchingStates matchState = MATCH_WITH_PROFILE;
        ProvisionType type = RELEASE;
        HapVerifyV2 verify;
        bool ret = verify.CheckProfileSignatureIsRight(matchState, type);
        EXPECT_EQ(ret, true);
    }
    /**
     * @tc.name: HapVerifyTest.HapVerify006
     * @tc.desc: The static function will return verify result of signed file;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyTest, HapVerify006, TestSize.Level0)
    {
        MatchingStates matchState = DO_NOT_MATCH;
        ProvisionType type = RELEASE;
        HapVerifyV2 verify;
        bool ret = verify.CheckProfileSignatureIsRight(matchState, type);
        EXPECT_EQ(ret, false);
    }
    /**
     * @tc.name: HapVerifyTest.HapVerify007
     * @tc.desc: The static function will return verify result of signed file;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyTest, HapVerify007, TestSize.Level0)
    {
        std::string outPutPath = "./test.log";
        PKCS7* p7 = nullptr;
        HapVerifyV2 verify;
        bool ret = verify.HapOutPutPkcs7(p7, outPutPath);
        EXPECT_EQ(ret, false);
    }
    /**
    * @tc.name: HapVerifyTest.HapVerify008
    * @tc.desc: The static function will return verify result of signed file;
    * @tc.type: FUNC
    */
    HWTEST_F(HapVerifyTest, HapVerify008, TestSize.Level0)
    {
        std::string profile = "";
        std::string ret = "111";
        HapVerifyV2 verify;
        int rets = verify.GetProfileContent(profile, ret);
        EXPECT_EQ(rets, -1);
    }
    /**
   * @tc.name: HapVerifyTest.HapVerify009
   * @tc.desc: The static function will return verify result of signed file;
   * @tc.type: FUNC
   */
    HWTEST_F(HapVerifyTest, HapVerify009, TestSize.Level0)
    {
        HapVerifyV2 verify;
        std::string profile = "{version-name: 1.0.0,version-code: 1,uuid: fe686e1b-3770-4824-a938-961b140a7c98}";
        std::string ret = "111";
        int rets = verify.GetProfileContent(profile, ret);
        EXPECT_EQ(rets, -1);
    }
    /**
     * @tc.name: HapVerifyTest.HapVerify010
     * @tc.desc: The static function will return verify result of signed file;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyTest, HapVerify010, TestSize.Level0)
    {
        HapVerifyV2 verify;
        Pkcs7Context pkcs7Context;
        ByteBuffer hapSignatureBlock;
        bool ret = verify.VerifyAppPkcs7(pkcs7Context, hapSignatureBlock);
        EXPECT_EQ(ret, false);
    }
    /**
     * @tc.name: HapVerifyTest.HapVerify0011
     * @tc.desc: The static function will return verify result of signed file;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyTest, HapVerify011, TestSize.Level0)
    {
        HapVerifyV2 verify;
        std::string filePath = "";
        HapVerifyResult hapVerifyV1Result;
        std::string outPath = "";
        int32_t ret = verify.ParseHapProfile(filePath, hapVerifyV1Result, outPath);
        EXPECT_EQ(ret, -1);
    }
    /**
     * @tc.name: HapVerifyTest.HapVerify012
     * @tc.desc: The static function will return verify result of signed file;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyTest, HapVerify012, TestSize.Level0)
    {
        HapVerifyV2 verify;
        std::string filePath = "";
        SignatureInfo hapSignInfo;
        int32_t ret = verify.ParseHapSignatureInfo(filePath, hapSignInfo);
        EXPECT_EQ(ret, -1);
    }
    /**
     * @tc.name: HapVerifyTest.HapVerify013
     * @tc.desc: The static function will return verify result of signed file;
     * @tc.type: FUNC
     */
    HWTEST_F(HapVerifyTest, HapVerify013, TestSize.Level0)
    {
        HapVerifyV2 verify;
        ProvisionInfo provisionInfo;
        verify.SetOrganization(provisionInfo);
    }

}
