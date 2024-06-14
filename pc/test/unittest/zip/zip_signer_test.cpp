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

#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "endof_central_directory.h"
#include "file_utils.h"
#include "hap_signer_block_utils.h"
#include "zip_entry.h"
#include "zip_signer.h"
#include "zip_utils.h"

namespace OHOS {
namespace SignatureTools {
class ZipSignerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: Test Init Function
 * @tc.desc: Test function of ZipSigner::Init() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, InitTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    EXPECT_EQ(zip->Init(inputFile), true);
}

/**
 * @tc.name: Test Init Function
 * @tc.desc: Test function of ZipSigner::Init() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, InitTest002, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/signed.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    EXPECT_EQ(zip->Init(inputFile), true);
}

/**
 * @tc.name: Test Init Function
 * @tc.desc: Test function of ZipSigner::Init() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, InitTest003, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned_empty.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    EXPECT_EQ(zip->Init(inputFile), false);
}

/**
 * @tc.name: Test Init Function
 * @tc.desc: Test function of ZipSigner::Init() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, InitTest004, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned_with_eocd.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    EXPECT_EQ(zip->Init(inputFile), false);
}

/**
 * @tc.name: Test Init Function
 * @tc.desc: Test function of ZipSigner::Init() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, InitTest005, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/dummy.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    EXPECT_EQ(zip->Init(inputFile), false);
}

/**
 * @tc.name: Test GetZipEntries Function
 * @tc.desc: Test function of ZipSigner::GetZipEntries() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, GetZipEntriesTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool zipRes = zip->Init(inputFile);
    std::vector<ZipEntry*> zipEntries = zip->GetZipEntries();
    EXPECT_EQ(zipRes && zipEntries.size() > 0, true);
}

/**
 * @tc.name: Test GetZipEntries Function
 * @tc.desc: Test function of ZipSigner::GetZipEntries() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, GetZipEntriesTest002, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned_with_eocd.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    EXPECT_EQ(zip->Init(inputFile), false);
}

/**
 * @tc.name: Test Alignment Function
 * @tc.desc: Test function of ZipSigner::Alignment() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, AlignmentTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool res = zip->Init(inputFile);
    int alignment = 4;
    zip->Alignment(alignment);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: Test Alignment Function
 * @tc.desc: Test function of ZipSigner::Alignment() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, AlignmentTest002, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool res = zip->Init(inputFile);
    EXPECT_EQ(res, true);
    std::vector<ZipEntry*> zipEntries = zip->GetZipEntries();
    int alignmentRes = zipEntries[0]->Alignment(0);
    EXPECT_EQ(alignmentRes, -1);
}

/**
 * @tc.name: Test Alignment Function
 * @tc.desc: Test function of ZipSigner::Alignment() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, AlignmentTest003, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool res = zip->Init(inputFile);
    EXPECT_EQ(res, true);
    std::vector<ZipEntry*> zipEntries = zip->GetZipEntries();
    int alignmentRes = zipEntries[0]->Alignment(102400);
    EXPECT_EQ(alignmentRes, -1);
}

/**
 * @tc.name: Test Alignment Function
 * @tc.desc: Test function of ZipSigner::Alignment() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, AlignmentTest004, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/mini.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool res = zip->Init(inputFile);
    EXPECT_EQ(res, true);
    std::vector<ZipEntry*> zipEntries = zip->GetZipEntries();
    int alignmentRes = zipEntries[0]->Alignment(4);
    EXPECT_EQ(alignmentRes, 1);
}

/**
 * @tc.name: Test RemoveSignBlock Function
 * @tc.desc: Test function of ZipSigner::RemoveSignBlock() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, RemoveSignBlockTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool res = zip->Init(inputFile);
    zip->RemoveSignBlock();
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: Test RemoveSignBlock Function
 * @tc.desc: Test function of ZipSigner::RemoveSignBlock() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, RemoveSignBlockTest002, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/signed.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool res = zip->Init(inputFile);
    zip->RemoveSignBlock();
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: Test GetSigningOffset Function
 * @tc.desc: Test function of ZipSigner::GetSigningOffset() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, GetSigningOffsetTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/signed.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool res = zip->Init(inputFile);
    uint64_t signingOffset = zip->GetSigningOffset();
    EXPECT_EQ(res && signingOffset != 0, true);
}

/**
 * @tc.name: Test GetCDOffset Function
 * @tc.desc: Test function of ZipSigner::GetCDOffset() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, GetCDOffsetTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/signed.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool res = zip->Init(inputFile);
    uint64_t cdOffset = zip->GetCDOffset();
    EXPECT_EQ(res && cdOffset != 0, true);
}

/**
 * @tc.name: Test GetEOCDOffset Function
 * @tc.desc: Test function of ZipSigner::GetEOCDOffset() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, GetEOCDOffsetTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/signed.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool res = zip->Init(inputFile);
    uint64_t eocdOffset = zip->GetEOCDOffset();
    EXPECT_EQ(res && eocdOffset != 0, true);
}

/**
 * @tc.name: Test ToFile Function
 * @tc.desc: Test function of ZipSigner::ToFile() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, ToFileTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::string outputFileName("/data/test/zip/unsigned-zip.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::ofstream outputFile(outputFileName, std::ios::binary | std::ios::trunc);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool initRes = zip->Init(inputFile);
    bool toFileRes = zip->ToFile(inputFile, outputFile);
    EXPECT_EQ(initRes && toFileRes, true);
}

/**
 * @tc.name: Test ToFile Function
 * @tc.desc: Test function of ZipSigner::ToFile() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, ToFileTest002, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::string outputFileName("");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::ofstream outputFile(outputFileName, std::ios::binary | std::ios::trunc);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool initRes = zip->Init(inputFile);
    bool toFileRes = zip->ToFile(inputFile, outputFile);
    EXPECT_EQ(initRes && !toFileRes, true);
}

/**
 * @tc.name: Test ToFile Function
 * @tc.desc: Test function of ZipSigner::ToFile() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, ToFileTest003, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::string outputFileName("");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::ofstream outputFile(outputFileName, std::ios::binary | std::ios::trunc);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool initRes = zip->Init(inputFile);

    std::ifstream bad("", std::ios::binary);

    bool toFileRes = zip->ToFile(bad, outputFile);
    EXPECT_EQ(initRes && !toFileRes, true);
}

/*
 * @tc.name: Alignment_Test_001
 * @tc.desc: Test function of ZipEntry::Alignment() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, ZipEntryAlignmentTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool res = zip->Init(inputFile);
    std::vector<ZipEntry*> zipEntries = zip->GetZipEntries();
    int alignment = 4;
    for (auto& zipEntry : zipEntries) {
        int add = zipEntry->Alignment(alignment);
        EXPECT_EQ(res && add > 0, true);
    }
}

/**
 * @tc.name: Test GetEOCDByBytes Function
 * @tc.desc: Test function of EndOfCentralDirectory::GetEOCDByBytes() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, EndOfCentralDirectoryGetEOCDByBytesTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream input(inputFileName, std::ios::binary);
    input.seekg(0, std::ios::end);
    uint64_t fileSize = input.tellg();
    input.seekg(0, std::ios::beg);

    int eocdLength = EndOfCentralDirectory::EOCD_LENGTH;
    uint64_t eocdOffset = (uint64_t)(fileSize - eocdLength);

    std::string retStr;
    int res = FileUtils::ReadFileByOffsetAndLength(input, eocdOffset, eocdLength, retStr);
    std::optional<EndOfCentralDirectory*> eocdByBytes = EndOfCentralDirectory::GetEOCDByBytes(retStr);
    EXPECT_EQ(res == 0 && eocdByBytes != std::nullopt, true);
}

/**
 * @tc.name: Test GetEOCDByBytes Function
 * @tc.desc: Test function of EndOfCentralDirectory::GetEOCDByBytes() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, EndOfCentralDirectoryGetEOCDByBytesTest002, testing::ext::TestSize.Level1)
{
    std::string str;
    std::optional<EndOfCentralDirectory*> eocdByBytes = EndOfCentralDirectory::GetEOCDByBytes(str);
    EXPECT_EQ(eocdByBytes == std::nullopt, true);
}

/**
 * @tc.name: Test GetEOCDByBytes Function
 * @tc.desc: Test function of EndOfCentralDirectory::GetEOCDByBytes() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, EndOfCentralDirectoryGetEOCDByBytesTest003, testing::ext::TestSize.Level1)
{
    std::string bytes(22, 0);
    std::optional<EndOfCentralDirectory*> eocdByBytes = EndOfCentralDirectory::GetEOCDByBytes(bytes);
    EXPECT_EQ(eocdByBytes == std::nullopt, true);
}

/**
 * @tc.name: Test GetEOCDByBytes Function
 * @tc.desc: Test function of EndOfCentralDirectory::GetEOCDByBytes() interface for FAIL with eocd length is wrong
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, EndOfCentralDirectoryGetEOCDByBytesTest004, testing::ext::TestSize.Level1)
{
    std::string bytes {
        80, 75, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    std::optional<EndOfCentralDirectory*> eocdByBytes = EndOfCentralDirectory::GetEOCDByBytes(bytes);
    EXPECT_EQ(eocdByBytes == std::nullopt, true);
}

/**
 * @tc.name: Test GetEOCDByBytes Function
 * @tc.desc: Test function of EndOfCentralDirectory::GetEOCDByBytes() interface for SUCCESS with comment.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, EndOfCentralDirectoryGetEOCDByBytesTest005, testing::ext::TestSize.Level1)
{
    std::string bytes {
        80, 75, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1
    };
    std::optional<EndOfCentralDirectory*> eocdByBytes = EndOfCentralDirectory::GetEOCDByBytes(bytes);
    EXPECT_EQ(eocdByBytes != std::nullopt, true);
    std::string eocdBytes = eocdByBytes.value()->ToBytes();
    EXPECT_EQ(eocdBytes.size() > 0, true);
}

/**
 * @tc.name: Test GetEOCDByBytes Function
 * @tc.desc: Test function of EndOfCentralDirectory::SetComment() interface.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, EndOfCentralDirectorySetCommentTest001, testing::ext::TestSize.Level1)
{
    std::string bytes {
        80, 75, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    std::optional<EndOfCentralDirectory*> eocdByBytes = EndOfCentralDirectory::GetEOCDByBytes(bytes);
    std::string comment { 1 };
    eocdByBytes.value()->SetComment(comment);
    EXPECT_EQ(eocdByBytes != std::nullopt, true);
}

/**
 * @tc.name: Test ToBytes Function
 * @tc.desc: Test function of EndOfCentralDirectory::ToBytes() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, EndOfCentralDirectoryToBytesTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool initRes = zip->Init(inputFile);
    EndOfCentralDirectory* eocd = zip->GetEndOfCentralDirectory();
    std::string eocdBytes = eocd->ToBytes();
    int signature = eocd->GetSIGNATURE();
    int diskNum = eocd->GetDiskNum();
    std::string comment = eocd->GetComment();
    EXPECT_EQ(initRes && eocd && eocdBytes.size() > 0 && signature != -1 && comment.size() == 0 && diskNum != -1,
        true);
}

/**
 * @tc.name: Test EndOfCentralDirectory Class
 * @tc.desc: Test function of EndOfCentralDirectory interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, EndOfCentralDirectoryTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool initRes = zip->Init(inputFile);
    EndOfCentralDirectory* eocd = zip->GetEndOfCentralDirectory();
    int eocdLength = eocd->GetEocdLength();
    int cdStartDiskNum = eocd->GetcDStartDiskNum();
    int diskCDNum = eocd->GetThisDiskCDNum();
    int eocdLen = eocd->GetLength();
    EXPECT_EQ(initRes && eocd && eocdLength > 0 && cdStartDiskNum != -1 && diskCDNum != -1 && eocdLen != -1,
        true);
}

/**
 * @tc.name: Test SetCentralDirectoryOffset Function
 * @tc.desc: Test function of ZipUtils::SetCentralDirectoryOffset() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, ZipUtilsSetCentralDirectoryOffsetTest001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    std::string outputFile("/data/test/zip/unsigned.hap");
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::pair<ByteBuffer, long long> eocdPair;
    EXPECT_EQ(HapSignerBlockUtils::FindEocdInHap(*outputHap, eocdPair), true);
    long long centralDirectoryOffset;
    EXPECT_EQ(HapSignerBlockUtils::GetCentralDirectoryOffset(eocdPair.first, eocdPair.second,
                  centralDirectoryOffset),
        true);
    long long newCentralDirOffset = centralDirectoryOffset + 10;
    eocdPair.first.SetPosition(0);
    EXPECT_EQ(ZipUtils::SetCentralDirectoryOffset(eocdPair.first, newCentralDirOffset), true);
}

/**
 * @tc.name: Test SetCentralDirectoryOffset Function
 * @tc.desc: Test function of ZipUtils::SetCentralDirectoryOffset() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, ZipUtilsSetCentralDirectoryOffsetTest002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    std::string outputFile("/data/test/zip/unsigned.hap");
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::pair<ByteBuffer, long long> eocdPair;
    EXPECT_EQ(HapSignerBlockUtils::FindEocdInHap(*outputHap, eocdPair), true);
    eocdPair.first.SetPosition(0);
    EXPECT_EQ(ZipUtils::SetCentralDirectoryOffset(eocdPair.first, -1), false);
}

/**
 * @tc.name: Test ZipEntryHeader Class
 * @tc.desc: Test function of ZipEntryHeader for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, ZipEntryHeaderTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool zipRes = zip->Init(inputFile);
    std::vector<ZipEntry*> zipEntries = zip->GetZipEntries();
    EXPECT_EQ(zipRes && zipEntries.size() > 0, true);
    ZipEntryData* zipEntryData = zipEntries[0]->GetZipEntryData();
    int crc32 = zipEntryData->GetZipEntryHeader()->GetCrc32();
    short lastTime = zipEntryData->GetZipEntryHeader()->GetLastTime();
    short lastData = zipEntryData->GetZipEntryHeader()->GetLastDate();
    long long compressedSize = zipEntryData->GetZipEntryHeader()->GetCompressedSize();
    long long unCompressedSize = zipEntryData->GetZipEntryHeader()->GetUnCompressedSize();
    int headerLength = zipEntryData->GetZipEntryHeader()->GetHeaderLength();
    int signature = zipEntryData->GetZipEntryHeader()->GetSIGNATURE();
    short version = zipEntryData->GetZipEntryHeader()->GetVersion();
    EXPECT_EQ(zipEntryData != nullptr && crc32 != -1 && lastTime != -1 && lastData != -1 && compressedSize != -1 &&
        unCompressedSize != -1 && headerLength != -1 && signature != -1 && version != -1, true);
}

/**
 * @tc.name: Test DataDescriptor Class
 * @tc.desc: Test function of DataDescriptor for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, DataDescriptorTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool zipRes = zip->Init(inputFile);
    std::vector<ZipEntry*> zipEntries = zip->GetZipEntries();
    EXPECT_EQ(zipRes && zipEntries.size() > 0, true);
    for (const auto& zipEntry : zipEntries) {
        ZipEntryData* zipEntryData = zipEntry->GetZipEntryData();
        DataDescriptor* dataDescriptor = zipEntryData->GetDataDescriptor();
        if (dataDescriptor) {
            uint64_t compressedSize = dataDescriptor->GetCompressedSize();
            uint64_t unCompressedSize = dataDescriptor->GetUnCompressedSize();
            int crc32 = dataDescriptor->GetCrc32();
            int signature = dataDescriptor->GetSIGNATURE();
            int desLength = dataDescriptor->GetDesLength();
            EXPECT_EQ(zipEntryData != nullptr && dataDescriptor != nullptr && compressedSize != -1 &&
            unCompressedSize != -1 && crc32 != -1 && signature != -1 && desLength != -1, true);
        } else {
            EXPECT_EQ(dataDescriptor == nullptr, true);
        }
    }
}

/**
 * @tc.name: Test DataDescriptor Class
 * @tc.desc: Test function of GetDataDescriptor for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, GetDataDescriptorTest001, testing::ext::TestSize.Level1)
{
    std::string bytes { 1 };
    EXPECT_EQ(DataDescriptor::GetDataDescriptor(bytes) == nullptr, true);
}

/**
 * @tc.name: Test DataDescriptor Class
 * @tc.desc: Test function of GetDataDescriptor for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, GetDataDescriptorTest002, testing::ext::TestSize.Level1)
{
    std::string bytes(16, 0);
    EXPECT_EQ(DataDescriptor::GetDataDescriptor(bytes) == nullptr, true);
}

/**
 * @tc.name: Test CentralDirectory Class
 * @tc.desc: Test function of CentralDirectory for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, CentralDirectoryTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    bool zipRes = zip->Init(inputFile);
    std::vector<ZipEntry*> zipEntries = zip->GetZipEntries();
    EXPECT_EQ(zipRes && zipEntries.size() > 0, true);
    CentralDirectory* cd = zipEntries[0]->GetCentralDirectory();
    int cdLength = cd->GetCdLength();
    int signature = cd->GetSIGNATURE();
    short flag = cd->GetFlag();
    short lastTime = cd->GetLastTime();
    short lastDate = cd->GetLastDate();
    int crc32 = cd->GetCrc32();
    std::string fileName = cd->GetFileName();
    short version = cd->GetVersion();
    short versionExtra = cd->GetVersionExtra();
    int diskNumStart = cd->GetDiskNumStart();
    short internalFile = cd->GetInternalFile();
    int externalFile = cd->GetExternalFile();
    std::string comment = cd->GetComment();
    EXPECT_EQ(cd != nullptr && cdLength != -1 && signature != -1 && flag != -1 && lastTime != -1 && lastDate != -1 &&
        crc32 != -1 && fileName.size() > 0 && version != -1 && versionExtra != -1 && diskNumStart != -1 &&
        internalFile != -1 && externalFile != -1 && comment.size() == 0, true);
}

/**
 * @tc.name: Test CentralDirectory Class
 * @tc.desc: Test function of CentralDirectory for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, CentralDirectoryTest002, testing::ext::TestSize.Level1)
{
    ByteBuffer bf(1);
    CentralDirectory* cd = new CentralDirectory();
    EXPECT_EQ(CentralDirectory::GetCentralDirectory(bf, cd), false);
    delete cd;
}

/**
 * @tc.name: Test CentralDirectory Class
 * @tc.desc: Test function of CentralDirectory for SUCCESS with comment.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, CentralDirectoryTest003, testing::ext::TestSize.Level1)
{
    std::string str;
    EXPECT_EQ(FileUtils::ReadFile("/data/test/zip/unsigned_only_cd.hap", str) == 0, true);
    ByteBuffer bf(str.c_str(), str.size());
    CentralDirectory* cd = new CentralDirectory();
    EXPECT_EQ(CentralDirectory::GetCentralDirectory(bf, cd), true);
    std::string cdBytes = cd->ToBytes();
    EXPECT_EQ(cdBytes.size() > 0, true);
}

/**
 * @tc.name: Test CentralDirectory Class
 * @tc.desc: Test function of CentralDirectory for SUCCESS without fileNameLength.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, CentralDirectoryTest004, testing::ext::TestSize.Level1)
{
    std::string str;
    EXPECT_EQ(FileUtils::ReadFile("/data/test/zip/unsigned_only_cd_v2.hap", str) == 0, true);
    ByteBuffer bf(str.c_str(), str.size());
    CentralDirectory* cd = new CentralDirectory();
    EXPECT_EQ(CentralDirectory::GetCentralDirectory(bf, cd), true);
    std::string cdBytes = cd->ToBytes();
    EXPECT_EQ(cdBytes.size() > 0, true);
}

/**
 * @tc.name: Test ZipEntryHeader Class
 * @tc.desc: Test function of GetZipEntryHeader for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, GetZipEntryHeaderTest001, testing::ext::TestSize.Level1)
{
    std::string headBytes { 1 };
    ZipEntryHeader* entryHeader = ZipEntryHeader::GetZipEntryHeader(headBytes);
    EXPECT_EQ(entryHeader == nullptr, true);
    delete entryHeader;
}

/**
 * @tc.name: Test ZipEntryData Class
 * @tc.desc: Test function of GetZipEntry for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(ZipSignerTest, GetZipEntryTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/zero.hap");
    std::ifstream inputFile(inputFileName, std::ios::binary);
    ZipEntryData* zipEntryData = ZipEntryData::GetZipEntry(inputFile, 0, 1024);
    EXPECT_EQ(zipEntryData == nullptr, true);
}
} // namespace SignatureTools
} // namespace OHOS