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
#include <fstream>
#include <gtest/gtest.h>
#include "verify_code_signature.h"
#include "verify_hap.h"
#include "packet_helper.h"

char* GetHapNoPacket(void);
char* GetSignedElfErr5Packet(void);
char* GetSignedElfErr6Packet(void);
char* GetSignedElfPacket(void);
char* GetSignedErrPacket(void);
char* GetSignedErr2Packet(void);
char* GetSignedErr3Packet(void);
char* GetSignedErr4Packet(void);
char* GetSignedErr5Packet(void);
char* GetSignedSoPacket(void);
char* GetUnsignedElfPacket(void);
char* GetUnSignedNoSoPacket(void);

using namespace OHOS::SignatureTools;

/*
 * 测试套件,固定写法
 */
class VerifyCodeSignatureTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void VerifyCodeSignatureTest::SetUpTestCase(void)
{
    (void)Base64DecodeStringToFile(GetHapNoPacket(), "./codeSigning/hap");
    (void)Base64DecodeStringToFile(GetSignedElfErr5Packet(), "./codeSigning/linuxout-signed-err5.elf");
    (void)Base64DecodeStringToFile(GetSignedElfErr6Packet(), "./codeSigning/linuxout-signed-err6.elf");
    (void)Base64DecodeStringToFile(GetSignedElfPacket(), "./codeSigning/linuxout-signed-err.elf");
    (void)Base64DecodeStringToFile(GetSignedErrPacket(), "./codeSigning/entry-default-signed-so-err.hap");
    (void)Base64DecodeStringToFile(GetSignedErr2Packet(), "./codeSigning/entry-default-signed-so-err2.hap");
    (void)Base64DecodeStringToFile(GetSignedErr3Packet(), "./codeSigning/entry-default-signed-so-err3.hap");
    (void)Base64DecodeStringToFile(GetSignedErr4Packet(), "./codeSigning/entry-default-signed-so-err4.hap");
    (void)Base64DecodeStringToFile(GetSignedErr5Packet(), "./codeSigning/entry-default-signed-so-err5.hap");
    (void)Base64DecodeStringToFile(GetSignedSoPacket(), "./codeSigning/entry-default-signed-so.hap");
    (void)Base64DecodeStringToFile(GetUnsignedElfPacket(), "./codeSigning/linuxout-unsigned.elf");
    (void)Base64DecodeStringToFile(GetUnSignedNoSoPacket(), "./codeSigning/phone-default-unsigned.hap");
}

void VerifyCodeSignatureTest::TearDownTestCase(void)
{
    (void)remove("./codeSigning/hap");
    (void)remove("./codeSigning/linuxout-signed-err5.elf");
    (void)remove("./codeSigning/linuxout-signed-err6.elf");
    (void)remove("./codeSigning/linuxout-signed-err.elf");
    (void)remove("./codeSigning/entry-default-signed-so-err.hap");
    (void)remove("./codeSigning/entry-default-signed-so-err2.hap");
    (void)remove("./codeSigning/entry-default-signed-so-err3.hap");
    (void)remove("./codeSigning/entry-default-signed-so-err4.hap");
    (void)remove("./codeSigning/entry-default-signed-so-err5.hap");
    (void)remove("./codeSigning/entry-default-signed-so.hap");
    (void)remove("./codeSigning/linuxout-unsigned.elf");
    (void)remove("./codeSigning/phone-default-unsigned.hap");
}

void VerifyCodeSignatureTest::SetUp()
{
}

void VerifyCodeSignatureTest::TearDown()
{
}

/**
 * @tc.name: AreVectorsEqual001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, AreVectorsEqual001, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> vec1{ 21, 53, 29, 18, -17, 56, 92, 60, 29, 10, 28, 18, 19, 52, 59, 92 };
    std::vector<int8_t> vec2{ 21, 53, 29, 18, -17, 56, 92, 60, 29, 10, 28, 18, 19, 52, 59, 92 };
    bool flag = VerifyCodeSignature::AreVectorsEqual(vec1, vec2);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: AreVectorsEqual002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, AreVectorsEqual002, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> vec1{ 21, 53, 29, 19, -17, 56, 92, 60, 29, 10, 28, 18, 19 };
    std::vector<int8_t> vec2{ 21, 53, 29, 18, -17, 56, 92, 60, 29, 10, 28, 18, 19, 52, 59, 92 };
    bool flag = VerifyCodeSignature::AreVectorsEqual(vec1, vec2);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyCodeSign
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyCodeSign, testing::ext::TestSize.Level1)
{
    std::pair<std::string, std::string> pairResult = std::make_pair("", "debug");
    std::string file = "./codeSigning/entry-default-signed-so.hap";
    int64_t offset = 1397151;
    int64_t length = 23193;
    std::string fileFormat = "hap";
    std::string profileContent = "";
    VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);
    CodeSignBlock csb;
    bool flag = VerifyCodeSignature::VerifyCodeSign(file, pairResult, csb);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyHap001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyHap001, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/entry-default-signed-so.hap";
    int64_t offset = 1397151;
    int64_t length = 23193;
    std::string fileFormat = "hap";
    std::string profileContent = "";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyHap002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyHap002, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/entry-default-signed-so.hap";
    int64_t offset = 1397151;
    int64_t length = 23193;
    std::string fileFormat = "";
    std::string profileContent = "";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: VerifyHap003
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyHap003, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/entry-default-signed-so.hap";
    int64_t offset = 1397151;
    int64_t length = 23194;
    std::string fileFormat = "hap";
    std::string profileContent = "";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyHap004
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyHap004, testing::ext::TestSize.Level1)
{
    std::string file = "";
    int64_t offset = 1397151;
    int64_t length = 23193;
    std::string fileFormat = "hap";
    std::string profileContent = "";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyHap005
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyHap005, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/entry-default-signed-so-err2.hap";
    int64_t offset = 1397151;
    int64_t length = 23221;
    std::string fileFormat = "hap";
    std::string profileContent = "{\"version-code\":1,\"version-name\":\"1.0.0\"}";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyHap006
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyHap006, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/entry-default-signed-so-err3.hap";
    int64_t offset = 1397151;
    int64_t length = 23193;
    std::string fileFormat = "hap";
    std::string profileContent = "{\"version-code\":1,\"version-name\":\"1.0.0\"}";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyHap007
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyHap007, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/entry-default-signed-so-err4.hap";
    int64_t offset = 1397151;
    int64_t length = 23193;
    std::string fileFormat = "hap";
    std::string profileContent = "{\"version-code\":1,\"version-name\":\"1.0.0\"}";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyHap008
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyHap008, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/entry-default-signed-so-err5.hap";
    int64_t offset = 1397151;
    int64_t length = 23193;
    std::string fileFormat = "hap";
    std::string profileContent = "{\"version-code\":1,\"version-name\":\"1.0.0\"}";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifySingleFile
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifySingleFile, testing::ext::TestSize.Level1)
{
    std::ifstream input;
    input.open("./codeSigning/entry-default-signed-so.hap", std::ios::binary);
    int64_t length = 4096;
    std::vector<int8_t> signature;
    int64_t merkleTreeOffset = 64;
    std::vector<int8_t> inMerkleTreeBytes;
    bool flag = VerifyCodeSignature::VerifySingleFile(input, length, signature, merkleTreeOffset, inMerkleTreeBytes);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyElf001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyElf001, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/linuxout-signed.elf";
    int64_t offset = 8216;
    int64_t length = 10516;
    std::string fileFormat = "elf";
    std::string profileContent = "{\"version-code\":1,\"version-name\":\"1.0.0\"}";
    bool flag = VerifyCodeSignature::VerifyElf(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyElf002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyElf002, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/linuxout-signed.elf";
    int64_t offset = 8216;
    int64_t length = 10516;
    std::string fileFormat = "hap";
    std::string profileContent = "{\"version-code\":1,\"version-name\":\"1.0.0\"}";
    bool flag = VerifyCodeSignature::VerifyElf(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyElf003
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyElf003, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/linuxout-signed111.elf";
    int64_t offset = 8216;
    int64_t length = 10516;
    std::string fileFormat = "elf";
    std::string profileContent = "{\"version-code\":1,\"version-name\":\"1.0.0\"}";
    bool flag = VerifyCodeSignature::VerifyElf(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyElf004
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyElf004, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/linuxout-signed.elf";
    int64_t offset = 8216;
    int64_t length = 2;
    std::string fileFormat = "elf";
    std::string profileContent = "{\"version-code\":1,\"version-name\":\"1.0.0\"}";
    bool flag = VerifyCodeSignature::VerifyElf(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyElf005
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyElf005, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/linuxout-signed.elf";
    int64_t offset = 8216;
    int64_t length = 10516;
    std::string fileFormat = "elf";
    std::string profileContent = "{\"version-code\":1,\"app-identifier\":\"111\"}";
    bool flag = VerifyCodeSignature::VerifyElf(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyElf006
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyElf006, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/linuxout-unsigned.elf";
    int64_t offset = 8216;
    int64_t length = 10516;
    std::string fileFormat = "elf";
    std::string profileContent = "{\"version-code\":1,\"version-name\":\"1.0.0\"}";
    bool flag = VerifyCodeSignature::VerifyElf(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyElf007
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyElf007, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/linuxout-signed-err5.elf";
    int64_t offset = 8216;
    int64_t length = 10516;
    std::string fileFormat = "elf";
    std::string profileContent = "{\"version-code\":1,\"version-name\":\"1.0.0\"}";
    bool flag = VerifyCodeSignature::VerifyElf(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyElf008
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyElf008, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/linuxout-signed-err6.elf";
    int64_t offset = 8216;
    int64_t length = 10499;
    std::string fileFormat = "elf";
    std::string profileContent = "{\"version-code\":1,\"version-name\":\"1.0.0\"}";
    bool flag = VerifyCodeSignature::VerifyElf(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: VerifyNativeLib001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyNativeLib001, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/phone-default-unsigned.hap";
    unzFile zFile = unzOpen(file.c_str());
    std::pair<std::string, std::string> pairResult;
    pairResult.first = "111";
    pairResult.second = "222";
    CodeSignBlock csb;
    bool flag = VerifyCodeSignature::VerifyNativeLib(csb, file, zFile, pairResult);
    unzClose(zFile);

    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: VerifyNativeLib002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, VerifyNativeLib002, testing::ext::TestSize.Level1)
{
    std::string file = "./codeSigning/entry-default-signed-so-err.hap";
    int64_t offset = 1397151;
    int64_t length = 23221;
    std::string fileFormat = "hap";
    std::string profileContent = "{\"version-code\":1,\"version-name\":\"1.0.0\"}";
    bool flag = VerifyCodeSignature::VerifyHap(file, offset, length, fileFormat, profileContent);

    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: CheckCodeSign001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, CheckCodeSign001, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./codeSigning/hap"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./codeSigning/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./codeSigning/xx.p7b"));

    HapVerifyResult hapVerifyResult;
    VerifyHap hapVerifyV2;
    int32_t ret = hapVerifyV2.Verify(options.GetString(Options::IN_FILE), hapVerifyResult, &options);

    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: CheckCodeSign002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(VerifyCodeSignatureTest, CheckCodeSign002, testing::ext::TestSize.Level1)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./codeSigning/entry-default-signed-so-err6.hap"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./codeSigning/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./codeSigning/xx.p7b"));

    HapVerifyResult hapVerifyResult;
    VerifyHap hapVerifyV2;
    int32_t ret = hapVerifyV2.Verify(options.GetString(Options::IN_FILE), hapVerifyResult, &options);

    EXPECT_NE(ret, 0);
}