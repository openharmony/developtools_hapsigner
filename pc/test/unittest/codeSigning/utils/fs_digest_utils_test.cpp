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

#include <memory>
#include <gtest/gtest.h>
#include "fs_digest_utils.h"

 /*
  * 测试套件,固定写法
  */
class DigestUtilsTest : public testing::Test {
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
 * @tc.name: addData001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(DigestUtilsTest, addData001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<DigestUtils> api = std::make_shared<DigestUtils>(HASH_SHA256);

    char charData[32] = { -66, -72, 8, -21, 1, 28, 23, 2, -1, -1, -1, -1, 15, 16, 40, -57, -34,
          -119, 1, 6, -76, -72, 8, -66, -72, 8, -66, -72, 8, -86, -50, 8 };
    std::string data(charData);
    api->AddData(data);

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: addData002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(DigestUtilsTest, addData002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<DigestUtils> api = std::make_shared<DigestUtils>(HASH_SHA256);

    char pData[32] = { -66, -72, 8, -21, 1, 28, 23, 2, -1, -1, -1, -1, 15, 16, 40, -57, -34,
                       -119, 1, 6, -76, -72, 8, -66, -72, 8, -66, -72, 8, -86, -50, 8 };
    int length = 32;
    api->AddData(pData, length);

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: DecodeBase64ToX509Certifate001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(DigestUtilsTest, DecodeBase64ToX509Certifate001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<DigestUtils> api = std::make_shared<DigestUtils>(HASH_SHA256);

    std::string encodestring = "-----BEGIN CERTIFICATE-----\n"
        "MIICMzCCAbegAwIBAgIEaOC/zDAMBggqhkjOPQQDAwUAMGMxCzAJBgNVBAYTAkNO\n"
        "MRQwEgYDVQQKEwtPcGVuSGFybW9ueTEZMBcGA1UECxMQT3Blbkhhcm1vbnkgVGVh\n"
        "bTEjMCEGA1UEAxMaT3Blbkhhcm1vbnkgQXBwbGljYXRpb24gQ0EwHhcNMjEwMjAy\n"
        "MTIxOTMxWhcNNDkxMjMxMTIxOTMxWjBoMQswCQYDVQQGEwJDTjEUMBIGA1UEChML\n"
        "T3Blbkhhcm1vbnkxGTAXBgNVBAsTEE9wZW5IYXJtb255IFRlYW0xKDAmBgNVBAMT\n"
        "H09wZW5IYXJtb255IEFwcGxpY2F0aW9uIFJlbGVhc2UwWTATBgcqhkjOPQIBBggq\n"
        "hkjOPQMBBwNCAATbYOCQQpW5fdkYHN45v0X3AHax12jPBdEDosFRIZ1eXmxOYzSG\n"
        "JwMfsHhUU90E8lI0TXYZnNmgM1sovubeQqATo1IwUDAfBgNVHSMEGDAWgBTbhrci\n"
        "FtULoUu33SV7ufEFfaItRzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFPtxruhl\n"
        "cRBQsJdwcZqLu9oNUVgaMAwGCCqGSM49BAMDBQADaAAwZQIxAJta0PQ2p4DIu/ps\n"
        "LMdLCDgQ5UH1l0B4PGhBlMgdi2zf8nk9spazEQI/0XNwpft8QAIwHSuA2WelVi/o\n"
        "zAlF08DnbJrOOtOnQq5wHOPlDYB4OtUzOYJk9scotrEnJxJzGsh/\n"
        "-----END CERTIFICATE-----\n";
    X509* pX509 = api->DecodeBase64ToX509Certifate(encodestring);

    EXPECT_NE(pX509, nullptr);
}

/**
 * @tc.name: DecodeBase64ToX509Certifate002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(DigestUtilsTest, DecodeBase64ToX509Certifate002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<DigestUtils> api = std::make_shared<DigestUtils>(HASH_SHA256);

    std::string encodestring;
    X509* pX509 = api->DecodeBase64ToX509Certifate(encodestring);

    EXPECT_EQ(pX509, nullptr);
}

/**
 * @tc.name: ParseBase64DecodedCRL
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(DigestUtilsTest, ParseBase64DecodedCRL, testing::ext::TestSize.Level1)
{
    std::shared_ptr<DigestUtils> api = std::make_shared<DigestUtils>(HASH_SHA256);

    std::string decodedCRL;
    X509_CRL* pX509_CRL = api->ParseBase64DecodedCRL(decodedCRL);

    EXPECT_EQ(pX509_CRL, nullptr);
}

/**
 * @tc.name: result
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(DigestUtilsTest, result, testing::ext::TestSize.Level1)
{
    std::shared_ptr<DigestUtils> api = std::make_shared<DigestUtils>(HASH_SHA256);

    DigestUtils::Type type = DigestUtils::Type::HEX;
    std::string str = api->Result(type);

    EXPECT_EQ(str.size(), 64);
}
