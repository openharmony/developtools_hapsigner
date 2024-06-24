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

#include "hap_verify_test.h"
#include <string>
#include <gtest/gtest.h>
#include <filesystem>
#include "profile_info.h"
#include "verify_hap.h"
#include "test_hap_file_data.h"
#include "hap_cert_verify_openssl_utils_test.h"
#include "test_const.h"
#include "test_hap_file_data.h"
#include "file_utils.h"
#include "random_access_file.h"
#include "signature_tools_log.h"
#include "verify_hap.h"
#include "hap_signer_block_utils.h"
#include "hap_verify_result.h"
#include "openssl/pem.h"
#include "options.h"

using namespace testing::ext;

namespace OHOS {
namespace SignatureTools {
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

void GenUnvaildHap(const std::string& path)
{
    std::ofstream outfile(path);
    if (!outfile) {
        std::cerr << "Unable to open file:" << path << std::endl;
        return;
    }
    outfile << "Hello, this is a Unvaild Hap.\n";
    outfile.close();
    return;
}

class VerifyHapTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void VerifyHapTest::SetUpTestCase(void)
{
    GenUnvaildHap("./hapVerify/unvaild.app");
    GenUnvaildHap("./hapVerify/unvaild.hap");
    GenUnvaildHap("./hapVerify/unvaild.hqf");
    GenUnvaildHap("./hapVerify/unvaild.hsp");
    GenUnvaildHap("./hapVerify/unvaild.txt");
}

void VerifyHapTest::TearDownTestCase(void)
{
    remove("./hapVerify/unvaild.app");
    remove("./hapVerify/unvaild.hap");
    remove("./hapVerify/unvaild.hqf");
    remove("./hapVerify/unvaild.hsp");
    remove("./hapVerify/unvaild.txt");
}

void VerifyHapTest::SetUp()
{
}

void VerifyHapTest::TearDown()
{
}

/**
 * @tc.name: Test CheckFilePath function
 * @tc.desc: The static function test whether input is a valid filepath;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, CheckFilePathTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input an too long filepath.
     * @tc.expected: step1. the return will be false.
     */
    VerifyHap v2;
    std::string filePath = HAP_FILE_ECC_SIGN_BASE64;
    std::string standardFilePath;
    ASSERT_FALSE(v2.CheckFilePath(filePath, standardFilePath));
}

/**
 * @tc.name: Test GenerateAppId function
 * @tc.desc: The static function will return whether generate appid successfully;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, GenerateAppIdTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input a null ProvisionInfo.
     * @tc.expected: step1. the return will be false.
     */
    VerifyHap v2;
    ProfileInfo provisionInfo;
    ASSERT_FALSE(v2.GenerateAppId(provisionInfo));
}

/**
 * @tc.name: Test GenerateFingerprint function
 * @tc.desc: The static function will return whether generate fingerprint successfully;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, GenerateFingerprintTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input a null ProvisionInfo.
     * @tc.expected: step1. the return will be false.
     */
    VerifyHap v2;
    ProfileInfo provisionInfo;
    ASSERT_FALSE(v2.GenerateFingerprint(provisionInfo));
}

/**
 * @tc.name: Test GenerateFingerprint function
 * @tc.desc: The static function will return whether generate fingerprint successfully;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, GenerateFingerprintTest002, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input ProvisionInfo with error distributionCertificate.
     * @tc.expected: step1. the return will be false.
     */
    VerifyHap v2;
    ProfileInfo provisionInfo;
    provisionInfo.bundleInfo.distributionCertificate = ERROR_CERTIFICATE;
    ASSERT_FALSE(v2.GenerateFingerprint(provisionInfo));
}

/**
 * @tc.name: Test GenerateFingerprint function
 * @tc.desc: The static function will return whether generate fingerprint successfully;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, GenerateFingerprintTest003, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input ProvisionInfo with error distributionCertificate.
     * @tc.expected: step1. the return will be false.
     */
    VerifyHap v2;
    ProfileInfo provisionInfo;
    provisionInfo.bundleInfo.developmentCertificate = ERROR_CERTIFICATE;
    ASSERT_FALSE(v2.GenerateFingerprint(provisionInfo));
}

/**
 * @tc.name: Test GenerateFingerprint function
 * @tc.desc: The static function will return whether generate fingerprint successfully;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, GenerateFingerprintTest004, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input ProvisionInfo with error distributionCertificate.
     * @tc.expected: step1. the return will be false.
     */
    VerifyHap v2;
    ProfileInfo provisionInfo;
    provisionInfo.bundleInfo.distributionCertificate = TEST_CERTIFICATE;
    ASSERT_TRUE(v2.GenerateFingerprint(provisionInfo));
}

/**
 * @tc.name: Test GenerateFingerprint function
 * @tc.desc: The static function will return whether generate fingerprint successfully;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, GenerateFingerprintTest005, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input ProvisionInfo with correct distributionCertificate.
     * @tc.expected: step1. the return will be true.
     */
    VerifyHap v2;
    ProfileInfo provisionInfo;
    provisionInfo.bundleInfo.developmentCertificate = TEST_CERTIFICATE;
    ASSERT_TRUE(v2.GenerateFingerprint(provisionInfo));
}

/**
 * @tc.name: Test VerifyProfileInfo function
 * @tc.desc: The static function will return result of verify profile info;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyProfileInfoTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. profile match with debug and profile type is release.
     * @tc.expected: step1. the return will be false.
     */
    VerifyHap v2;
    Pkcs7Context pkcs7Context;
    Pkcs7Context profileContext;
    ProfileInfo provisionInfo;
    profileContext.matchResult.matchState = MATCH_WITH_PROFILE_DEBUG;
    provisionInfo.type = ProvisionType::RELEASE;
    ASSERT_FALSE(v2.VerifyProfileInfo(pkcs7Context, profileContext, provisionInfo));
}

/**
 * @tc.name: Test ParseAndVerifyProfileIfNeed function
 * @tc.desc: The static function will return result of ParseAndVerifyProfileIfNeed;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, ParseAndVerifyProfileIfNeedTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input a null profile.
     * @tc.expected: step1. the return will be false.
     */
    VerifyHap v2;
    std::string profile;
    ProfileInfo provisionInfo;
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
HWTEST_F(VerifyHapTest, GetDigestAndAlgorithmTest001, TestSize.Level1)
{
    /*
     * @tc.steps: step1. input an error pkcs7 content.
     * @tc.expected: step1. the return will be false.
     */
    VerifyHap v2;
    Pkcs7Context digest;
    digest.content.SetCapacity(TEST_FILE_BLOCK_LENGTH);
    ASSERT_FALSE(v2.GetDigestAndAlgorithm(digest));
}


/**
 * @tc.name: VerifyHapTest.Verify001
 * @tc.desc: The static function will return verify result;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify001, TestSize.Level0)
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

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    OHOS::SignatureTools::HapVerifyResultCode targetResult = OHOS::SignatureTools::FILE_PATH_INVALID;
    ASSERT_TRUE(resultCode == targetResult);
    std::ofstream appFile;
    appFile.open(errorFile.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
    ASSERT_TRUE(appFile.is_open());
    appFile.close();
    resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    ASSERT_TRUE(resultCode == targetResult);
}


/**
 * @tc.name: VerifyHapTest.HapVerifyOsApp001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, HapVerifyOsApp001, TestSize.Level0)
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

    VerifyHap verify;
    int32_t ret = verify.Verify(filePath, hapVerifyResult, &options);
    ASSERT_EQ(ret, OHOS::SignatureTools::VERIFY_SUCCESS);
}

/**
 * @tc.name: VerifyHapTest.Verify002
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify002, TestSize.Level0)
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
    VerifyHap verify;
    ASSERT_TRUE(verify.Verify(filePath, hapVerifyResult, &options) == OHOS::SignatureTools::VERIFY_SUCCESS);
    // /*
    //     * @tc.steps: step2. check verify result.
    //     * @tc.expected: step2. cert version is 1, certChains Len is 3.
    //     */
    OHOS::SignatureTools::ProfileInfo profile = hapVerifyResult.GetProvisionInfo();
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
    ASSERT_EQ(verify.Verify(errorfilePath, verifyRet, &options), OHOS::SignatureTools::VERIFY_CODE_SIGN_FAIL);
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
    ASSERT_EQ(verify.Verify(errorfilePath, verifyRet, &options), OHOS::SignatureTools::VERIFY_CODE_SIGN_FAIL);
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
    ASSERT_EQ(verify.Verify(errorfilePath, verifyRet, &options), OHOS::SignatureTools::VERIFY_CODE_SIGN_FAIL);
}

/**
 * @tc.name: VerifyHapTest.Verify003
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */

HWTEST_F(VerifyHapTest, Verify004, TestSize.Level0)
{
    /*
        * @tc.steps: step1. input a invalid path to function of HapVerify.
        * @tc.expected: step1. the return will be FILE_PATH_INVALID.
        */
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.pem";
    options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

    VerifyHap verify;
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
    int32_t resultCode = verify.Verify(rightFile, hapVerifyResult, &options);
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
    resultCode = verify.Verify(rightFile1, hapVerifyResult, &options);
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
    resultCode = verify.Verify(invalidFile, hapVerifyResult, &options);
    ASSERT_TRUE(resultCode == OHOS::SignatureTools::SIGNATURE_NOT_FOUND);
}
/**
 * @tc.name: VerifyHapTest.Verify007
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify007, TestSize.Level0)
{
    std::string outPutPath = "./test.log";
    PKCS7* p7 = nullptr;
    VerifyHap verify;
    bool ret = verify.HapOutPutPkcs7(p7, outPutPath);
    EXPECT_EQ(ret, false);
}
/**
* @tc.name: VerifyHapTest.Verify008
* @tc.desc: The static function will return verify result of signed file;
* @tc.type: FUNC
*/
HWTEST_F(VerifyHapTest, Verify008, TestSize.Level0)
{
    std::string profile = "";
    std::string ret = "111";
    VerifyHap verify;
    int rets = verify.GetProfileContent(profile, ret);
    EXPECT_EQ(rets, -1);
}
/**
 * @tc.name: VerifyHapTest.Verify009
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify009, TestSize.Level0)
{
    VerifyHap verify;
    std::string profile = "{version-name: 1.0.0,version-code: 1,uuid: fe686e1b-3770-4824-a938-961b140a7c98}";
    std::string ret = "111";
    int rets = verify.GetProfileContent(profile, ret);
    EXPECT_EQ(rets, -1);
}
/**
 * @tc.name: VerifyHapTest.Verify010
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify010, TestSize.Level0)
{
    VerifyHap verify;
    Pkcs7Context pkcs7Context;
    ByteBuffer hapSignatureBlock;
    bool ret = verify.VerifyAppPkcs7(pkcs7Context, hapSignatureBlock);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: VerifyHapTest.Verify013
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify013, TestSize.Level0)
{
    VerifyHap verify;
    ProfileInfo provisionInfo;
    verify.SetOrganization(provisionInfo);
}
/**
 * @tc.name: VerifyHapTest.Verify014
 * @tc.desc: The static function will return verify result;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify014, TestSize.Level0)
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

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    OHOS::SignatureTools::HapVerifyResultCode targetResult = OHOS::SignatureTools::FILE_PATH_INVALID;
    ASSERT_TRUE(resultCode == targetResult);
    std::ofstream appFile;
    appFile.open(errorFile.c_str(), std::ios::binary | std::ios::out | std::ios::trunc);
    ASSERT_TRUE(appFile.is_open());
    appFile.close();
    resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
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
    resultCode = verify.Verify(rightFile, hapVerifyResult, &options);
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
    resultCode = verify.Verify(rightFile1, hapVerifyResult, &options);
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
    resultCode = verify.Verify(invalidFile, hapVerifyResult, &options);
    ASSERT_TRUE(resultCode == OHOS::SignatureTools::SIGNATURE_NOT_FOUND);
}


/**
 * @tc.name: VerifyHapTest.Verify015
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify015, TestSize.Level0)
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

    VerifyHap verify;
    int32_t ret = verify.Verify(filePath, hapVerifyResult, &options);
    ASSERT_EQ(ret, OHOS::SignatureTools::VERIFY_SUCCESS);
}

/**
 * @tc.name: VerifyHapTest.Verify016
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify016, TestSize.Level0)
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
    VerifyHap verify;
    ASSERT_TRUE(verify.Verify(filePath, hapVerifyResult, &options) == OHOS::SignatureTools::VERIFY_SUCCESS);
    // /*
    //     * @tc.steps: step2. check verify result.
    //     * @tc.expected: step2. cert version is 1, certChains Len is 3.
    //     */
    OHOS::SignatureTools::ProfileInfo profile = hapVerifyResult.GetProvisionInfo();
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
    ASSERT_EQ(verify.Verify(errorfilePath, verifyRet, &options), OHOS::SignatureTools::VERIFY_CODE_SIGN_FAIL);
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
    ASSERT_EQ(verify.Verify(errorfilePath, verifyRet, &options), OHOS::SignatureTools::VERIFY_CODE_SIGN_FAIL);
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
    ASSERT_EQ(verify.Verify(errorfilePath, verifyRet, &options), OHOS::SignatureTools::VERIFY_CODE_SIGN_FAIL);
}

/**
 * @tc.name: VerifyHapTest.Verify021
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify021, TestSize.Level0)
{
    std::string outPutPath = "./test.log";
    PKCS7* p7 = nullptr;
    VerifyHap verify;
    bool ret = verify.HapOutPutPkcs7(p7, outPutPath);
    EXPECT_EQ(ret, false);
}
/**
* @tc.name: VerifyHapTest.Verify022
* @tc.desc: The static function will return verify result of signed file;
* @tc.type: FUNC
*/
HWTEST_F(VerifyHapTest, Verify022, TestSize.Level0)
{
    std::string profile = "";
    std::string ret = "111";
    VerifyHap verify;
    int rets = verify.GetProfileContent(profile, ret);
    EXPECT_EQ(rets, -1);
}
/**
 * @tc.name: VerifyHapTest.Verify023
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify023, TestSize.Level0)
{
    VerifyHap verify;
    std::string profile = "{version-name: 1.0.0,version-code: 1,uuid: fe686e1b-3770-4824-a938-961b140a7c98}";
    std::string ret = "111";
    int rets = verify.GetProfileContent(profile, ret);
    EXPECT_EQ(rets, -1);
}
/**
 * @tc.name: VerifyHapTest.Verify024
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify024, TestSize.Level0)
{
    VerifyHap verify;
    Pkcs7Context pkcs7Context;
    ByteBuffer hapSignatureBlock;
    bool ret = verify.VerifyAppPkcs7(pkcs7Context, hapSignatureBlock);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: VerifyHapTest.Verify027
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, Verify027, TestSize.Level0)
{
    VerifyHap verify;
    ProfileInfo provisionInfo;
    verify.SetOrganization(provisionInfo);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError001, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.pem";
    options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

    std::string errorFile = "./hapVerify/unvaild.hqf";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError002, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.pem";
    options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

    std::string errorFile = "./hapVerify/unvaild.hap";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError003, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.pem";
    options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

    std::string errorFile = "./hapVerify/unvaild.app";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError004, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.pem";
    options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

    std::string errorFile = "./hapVerify/unvaild.hsp";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError005, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.pem";
    options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

    std::string errorFile = "./hapVerify/unvaild.txt";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError006, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify_nohave/certchain.pem";
    options[Options::OUT_PROFILE] = "./hapVerify_nohava/profile.p7b";

    std::string errorFile = "./hapVerify/phone-default-signed.hap";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError007, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string outCertChain = "./hapVerify_nohave/certchain.pem";
    std::string outProfile = "./hapVerify/profile.p7b";
    (*params)["outCertChain"] = outCertChain;
    (*params)["outProfile"] = outProfile;


    std::string errorFile = "./hapVerify/phone-default-signed.hap";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, params.get());
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError008, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string outCertChain = "./hapVerify/certchain.pem";
    std::string outProfile = "./hapVerify_nohave/profile.p7b";
    (*params)["outCertChain"] = outCertChain;
    (*params)["outProfile"] = outProfile;


    std::string errorFile = "./hapVerify/phone-default-signed.hap";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, params.get());
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError009, TestSize.Level0)
{
    Pkcs7Context pkcs7Context_t;
    MatchingResult t;
    t.matchState = MATCH_WITH_SIGN;
    t.source = APP_THIRD_PARTY_PRELOAD;
    pkcs7Context_t.matchResult = t;
    VerifyHap verify;
    bool ret = verify.VerifyProfileSignature(pkcs7Context_t, pkcs7Context_t);
    EXPECT_NE(ret, true);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError010, TestSize.Level0)
{
    AppDistType type = APP_GALLERY;
    ProfileInfo provisionInfo;
    VerifyHap verify;
    bool ret = verify.IsAppDistributedTypeAllowInstall(type, provisionInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError011, TestSize.Level0)
{
    AppDistType type = NONE_TYPE;
    ProfileInfo provisionInfo;
    VerifyHap verify;
    bool ret = verify.IsAppDistributedTypeAllowInstall(type, provisionInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError012, TestSize.Level0)
{
    VerifyHap verify;
    Pkcs7Context digest;
    ByteBuffer content("1", 1);
    digest.content = content;
    bool ret = verify.GetDigestAndAlgorithm(digest);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError013, TestSize.Level0)
{
    VerifyHap verify;
    Pkcs7Context digest;
    ByteBuffer content("12345678912345", 14);
    digest.content = content;
    bool ret = verify.GetDigestAndAlgorithm(digest);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError014, TestSize.Level0)
{
    VerifyHap verify;
    Pkcs7Context digest;
    ByteBuffer content("123456789123456789123456789", 27);
    digest.content = content;
    bool ret = verify.GetDigestAndAlgorithm(digest);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError015, TestSize.Level0)
{
    VerifyHap verify;
    Pkcs7Context digest;
    ByteBuffer content("123456789123456789123456789", 19);
    digest.content = content;
    bool ret = verify.GetDigestAndAlgorithm(digest);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: VerifyHapTest.VerifyHapError001
* @tc.desc: The static function will return verify result of signed file;
* @tc.type: FUNC
*/
HWTEST_F(VerifyHapTest, VerifyHapError016, TestSize.Level0)
{
    bool ret = false;
    VerifyHap verify;
    Pkcs7Context pkcs7Context;
    MatchingResult t;
    t.matchState = MATCH_WITH_SIGN;
    t.source = APP_GALLARY;
    pkcs7Context.matchResult = t;
    ByteBuffer hapProfileBlock;
    ProfileInfo provisionInfo;
    verify.SetProfileBlockData(pkcs7Context, hapProfileBlock, provisionInfo);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: VerifyHapTest.VerifyHapError001
* @tc.desc: The static function will return verify result of signed file;
* @tc.type: FUNC
*/
HWTEST_F(VerifyHapTest, VerifyHapError017, TestSize.Level0)
{
    bool ret = false;
    VerifyHap verify;
    Pkcs7Context pkcs7Context;
    MatchingResult t;
    t.matchState = MATCH_WITH_SIGN;
    t.source = APP_THIRD_PARTY_PRELOAD;
    pkcs7Context.matchResult = t;
    ByteBuffer hapProfileBlock;
    ProfileInfo provisionInfo;
    verify.SetProfileBlockData(pkcs7Context, hapProfileBlock, provisionInfo);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: VerifyHapTest.VerifyHapError001
* @tc.desc: The static function will return verify result of signed file;
* @tc.type: FUNC
*/
HWTEST_F(VerifyHapTest, VerifyHapError018, TestSize.Level0)
{
    bool ret = false;
    VerifyHap verify;
    Pkcs7Context pkcs7Context;
    MatchingResult t;
    t.matchState = MATCH_WITH_SIGN;
    t.source = APP_THIRD_PARTY_PRELOAD;
    pkcs7Context.matchResult = t;
    ByteBuffer hapProfileBlock;
    ProfileInfo provisionInfo;
    verify.SetProfileBlockData(pkcs7Context, hapProfileBlock, provisionInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError019, TestSize.Level0)
{
    bool ret = false;
    VerifyHap verify;
    Pkcs7Context pkcs7Context;
    Pkcs7Context profileContext;
    ProfileInfo provisionInfo;
    provisionInfo.type = ProvisionType::RELEASE;
    provisionInfo.distributionType = APP_GALLERY;
    ret = verify.VerifyProfileInfo(pkcs7Context, profileContext, provisionInfo);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError024, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.cer";
    options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

    std::string errorFile = "./hapVerify/test.hap";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError025, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.cer";
    options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

    std::string errorFile = "./hapVerify/test1.hap";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError026, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.cer";
    options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

    std::string errorFile = "./hapVerify/test2.hap";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError027, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.cer";
    options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

    std::string errorFile = "./hapVerify/test3.hap";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError028, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.cer";
    options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

    std::string errorFile = "./hapVerify/test4.hap";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    EXPECT_NE(resultCode, 0);
}

/**
 * @tc.name: VerifyHapTest.VerifyHapError001
 * @tc.desc: The static function will return verify result of signed file;
 * @tc.type: FUNC
 */
HWTEST_F(VerifyHapTest, VerifyHapError029, TestSize.Level0)
{
    OHOS::SignatureTools::HapVerifyResult hapVerifyResult;
    Options options;
    options[Options::OUT_CERT_CHAIN] = "./hapVerify/certchain.cer";
    options[Options::OUT_PROFILE] = "./hapVerify/profile.p7b";

    std::string errorFile = "./hapVerify/test5.hap";

    VerifyHap verify;
    int32_t resultCode = verify.Verify(errorFile, hapVerifyResult, &options);
    EXPECT_NE(resultCode, 0);
}
}
}
