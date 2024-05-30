/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <utility>
#include "random_access_file.h"
#include "data_source.h"
#include "random_access_file_zip_data_input.h"
#include "random_access_file_zip_data_output.h"
#include "signing_block_utils.h"

using namespace OHOS::SignatureTools;

class RandomAccessFile2Test : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: Test Init Function
 * @tc.desc: Test function of RandomAccessFile::Init() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, InitTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned-zip.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    bool res = outputHap->Init(inputFileName);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: Test Init Function
 * @tc.desc: Test function of RandomAccessFile::Init() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, InitTest002, testing::ext::TestSize.Level1)
{
    std::string inputFileName("");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    bool res = outputHap->Init(inputFileName);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: Test WriteToFile Function
 * @tc.desc: Test function of RandomAccessFile::WriteToFile() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, WriteToFileTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned-zip.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    bool res = outputHap->Init(inputFileName);
    EXPECT_EQ(res, true);
    std::vector<char> buffer{1};
    EXPECT_EQ(outputHap->WriteToFile(buffer, 0, 0, 1) > 0, true);
}

/**
 * @tc.name: Test WriteToFile Function
 * @tc.desc: Test function of RandomAccessFile::WriteToFile() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, WriteToFileTest002, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned-zip.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    bool res = outputHap->Init(inputFileName);
    EXPECT_EQ(res, true);
    std::vector<char> buffer;
    EXPECT_EQ(outputHap->WriteToFile(buffer, 0, 0, 0), -1);
}

/**
 * @tc.name: Test RandomAccessFileZipDataInput Function
 * @tc.desc: Test function of RandomAccessFileZipDataInput::RandomAccessFileZipDataInput() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataInputTest001, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileZipDataInput>(*outputHap, 1, 1);
    EXPECT_EQ(outputHapIn != nullptr, true);
}

/**
 * @tc.name: Test RandomAccessFileZipDataInput Function
 * @tc.desc: Test function of RandomAccessFileZipDataInput::RandomAccessFileZipDataInput() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataInputTest002, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileZipDataInput>(*outputHap, 1, -1);
    EXPECT_EQ(outputHapIn != nullptr, true);
}

/**
 * @tc.name: Test RandomAccessFileZipDataInput Function
 * @tc.desc: Test function of RandomAccessFileZipDataInput::RandomAccessFileZipDataInput() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataInputTest003, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileZipDataInput>(*outputHap, -1, 1);
    EXPECT_EQ(outputHapIn != nullptr, true);
}

/**
 * @tc.name: Test Slice Function
 * @tc.desc: Test function of RandomAccessFileZipDataInput::Slice() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataInputSliceTest001, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileZipDataInput>(*outputHap);
    std::pair<ByteBuffer, long long> eocdPair;
    EXPECT_EQ(HapSigningBlockUtils::FindEocdInHap(*outputHap, eocdPair), true);
    long long centralDirectoryOffset;
    EXPECT_EQ(HapSigningBlockUtils::GetCentralDirectoryOffset(eocdPair.first,
                                                              eocdPair.second,
                                                              centralDirectoryOffset),
              true);
    DataSource* beforeCentralDir = outputHapIn->Slice(0, centralDirectoryOffset);
    EXPECT_EQ(beforeCentralDir != nullptr, true);
}

/**
 * @tc.name: Test Slice Function
 * @tc.desc: Test function of RandomAccessFileZipDataInput::Slice() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataInputSliceTest002, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileZipDataInput>(*outputHap, 0, 10);
    DataSource* beforeCentralDir = outputHapIn->Slice(-1, 10);
    EXPECT_EQ(beforeCentralDir == nullptr, true);
}

/**
 * @tc.name: Test Slice Function
 * @tc.desc: Test function of RandomAccessFileZipDataInput::Slice() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataInputSliceTest003, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileZipDataInput>(*outputHap, 0, 10);
    DataSource* beforeCentralDir = outputHapIn->Slice(0, -1);
    EXPECT_EQ(beforeCentralDir == nullptr, true);
}

/**
 * @tc.name: Test Slice Function
 * @tc.desc: Test function of RandomAccessFileZipDataInput::Slice() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataInputSliceTest004, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileZipDataInput>(*outputHap, 0, 10);
    DataSource* beforeCentralDir = outputHapIn->Slice(20, 1);
    EXPECT_EQ(beforeCentralDir == nullptr, true);
}

/**
 * @tc.name: Test Slice Function
 * @tc.desc: Test function of RandomAccessFileZipDataInput::Slice() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataInputSliceTest005, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileZipDataInput>(*outputHap, 0, 10);
    DataSource* beforeCentralDir = outputHapIn->Slice(0, 20);
    EXPECT_EQ(beforeCentralDir == nullptr, true);
}

/**
 * @tc.name: Test CreateByteBuffer Function
 * @tc.desc: Test function of RandomAccessFileZipDataInput::CreateByteBuffer() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataInputCreateByteBufferTest001, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileZipDataInput>(*outputHap);
    std::pair<ByteBuffer, long long> eocdPair;
    EXPECT_EQ(HapSigningBlockUtils::FindEocdInHap(*outputHap, eocdPair), true);
    long long centralDirectoryOffset;
    EXPECT_EQ(HapSigningBlockUtils::GetCentralDirectoryOffset(eocdPair.first,
                                                              eocdPair.second,
                                                              centralDirectoryOffset),
              true);
    DataSource* beforeCentralDir = outputHapIn->Slice(0, centralDirectoryOffset);
    EXPECT_EQ(beforeCentralDir != nullptr, true);
    long centralDirectorySize;
    EXPECT_EQ(HapSigningBlockUtils::GetCentralDirectorySize(eocdPair.first, centralDirectorySize), true);
    ByteBuffer centralDirBuffer = outputHapIn->CreateByteBuffer(centralDirectoryOffset, centralDirectorySize);
    EXPECT_EQ(centralDirBuffer.GetCapacity() > 0, true);
}

/**
 * @tc.name: Test CreateByteBuffer Function
 * @tc.desc: Test function of RandomAccessFileZipDataInput::CreateByteBuffer() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataInputCreateByteBufferTest002, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileZipDataInput>(*outputHap);
    std::pair<ByteBuffer, long long> eocdPair;
    EXPECT_EQ(HapSigningBlockUtils::FindEocdInHap(*outputHap, eocdPair), true);
    ByteBuffer centralDirBuffer = outputHapIn->CreateByteBuffer(0, -1);
    EXPECT_EQ(centralDirBuffer.GetCapacity() == 0, true);
}

/**
 * @tc.name: Test Write ByteBuffer Function
 * @tc.desc: Test function of RandomAccessFileZipDataOutput::Write() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataOutputWriteTest001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    std::string outputFile("/data/test/zip/unsigned.hap");
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::pair<ByteBuffer, long long> eocdPair;
    EXPECT_EQ(HapSigningBlockUtils::FindEocdInHap(*outputHap, eocdPair), true);
    long long centralDirectoryOffset;
    EXPECT_EQ(HapSigningBlockUtils::GetCentralDirectoryOffset(eocdPair.first,
                                                              eocdPair.second,
                                                              centralDirectoryOffset),
              true);
    std::shared_ptr<RandomAccessFileZipDataOutput> outputHapOut =
        std::make_shared<RandomAccessFileZipDataOutput>(outputHap.get(), centralDirectoryOffset);
    ByteBuffer signingBlock(1);
    signingBlock.PutByte(1);
    EXPECT_EQ(outputHapOut->Write(signingBlock), true);
}

/**
 * @tc.name: Test Write ByteBuffer Function
 * @tc.desc: Test function of RandomAccessFileZipDataOutput::Write() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataOutputWriteTest002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    std::string outputFile("/data/test/zip/unsigned.hap");
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::pair<ByteBuffer, long long> eocdPair;
    EXPECT_EQ(HapSigningBlockUtils::FindEocdInHap(*outputHap, eocdPair), true);
    long long centralDirectoryOffset;
    EXPECT_EQ(HapSigningBlockUtils::GetCentralDirectoryOffset(eocdPair.first,
                                                              eocdPair.second,
                                                              centralDirectoryOffset),
              true);
    std::shared_ptr<RandomAccessFileZipDataOutput> outputHapOut =
        std::make_shared<RandomAccessFileZipDataOutput>(outputHap.get(), centralDirectoryOffset);
    ByteBuffer signingBlock;
    EXPECT_EQ(outputHapOut->Write(signingBlock), false);
}

/**
 * @tc.name: Test Write ByteBuffer Function
 * @tc.desc: Test function of RandomAccessFileZipDataOutput() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataOutputTest001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    std::string outputFile("/data/test/zip/unsigned.hap");
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<RandomAccessFileZipDataOutput> outputHapOut =
        std::make_shared<RandomAccessFileZipDataOutput>(outputHap.get());
    EXPECT_EQ(outputHapOut != nullptr, true);
}

/**
 * @tc.name: Test Write ByteBuffer Function
 * @tc.desc: Test function of RandomAccessFileZipDataOutput() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFile2Test, RandomAccessFileZipDataOutputTest002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    std::string outputFile("/data/test/zip/unsigned.hap");
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<RandomAccessFileZipDataOutput> outputHapOut =
        std::make_shared<RandomAccessFileZipDataOutput>(outputHap.get(), -1);
    EXPECT_EQ(outputHapOut != nullptr, true);
}