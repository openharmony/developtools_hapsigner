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

#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <utility>

#include "data_source.h"
#include "hap_signer_block_utils.h"
#include "random_access_file.h"
#include "random_access_file_input.h"
#include "random_access_file_output.h"

namespace OHOS {
namespace SignatureTools {
class RandomAccessFileInputOutputTest : public testing::Test {
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
HWTEST_F(RandomAccessFileInputOutputTest, InitTest001, testing::ext::TestSize.Level1)
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
HWTEST_F(RandomAccessFileInputOutputTest, InitTest002, testing::ext::TestSize.Level1)
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
HWTEST_F(RandomAccessFileInputOutputTest, WriteToFileTest001, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned-zip.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    bool res = outputHap->Init(inputFileName);
    EXPECT_EQ(res, true);
    ByteBuffer buffer(1);
    buffer.PutByte(1);
    EXPECT_EQ(outputHap->WriteToFile(buffer, 0, 1) > 0, true);
}

/**
 * @tc.name: Test WriteToFile Function
 * @tc.desc: Test function of RandomAccessFile::WriteToFile() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, WriteToFileTest002, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned-zip.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    bool res = outputHap->Init(inputFileName);
    EXPECT_EQ(res, true);
    ByteBuffer buffer;
    EXPECT_EQ(outputHap->WriteToFile(buffer, 0, 0), -1);
}

/**
 * @tc.name: Test WriteToFile Function
 * @tc.desc: Test function of RandomAccessFile::WriteToFile() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, WriteToFileTest003, testing::ext::TestSize.Level1)
{
    std::string inputFileName("/data/test/zip/unsigned-zip.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    bool res = outputHap->Init(inputFileName);
    EXPECT_EQ(res, true);
    ByteBuffer buffer(1);
    buffer.PutByte(1);
    EXPECT_EQ(outputHap->WriteToFile(buffer, -1, 0), READ_OFFSET_OUT_OF_RANGE);
}

/**
 * @tc.name: Test RandomAccessFileInput Function
 * @tc.desc: Test function of RandomAccessFileInput::RandomAccessFileInput() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileInputTest001, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileInput>(*outputHap, 1, 1);
    EXPECT_EQ(outputHapIn != nullptr, true);
}

/**
 * @tc.name: Test RandomAccessFileInput Function
 * @tc.desc: Test function of RandomAccessFileInput::RandomAccessFileInput() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileInputTest002, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileInput>(*outputHap, 1, -1);
    EXPECT_EQ(outputHapIn != nullptr, true);
}

/**
 * @tc.name: Test RandomAccessFileInput Function
 * @tc.desc: Test function of RandomAccessFileInput::RandomAccessFileInput() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileInputTest003, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileInput>(*outputHap, -1, 1);
    EXPECT_EQ(outputHapIn != nullptr, true);
}

/**
 * @tc.name: Test Slice Function
 * @tc.desc: Test function of RandomAccessFileInput::Slice() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileInputSliceTest001, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileInput>(*outputHap);
    std::pair<ByteBuffer, long long> eocdPair;
    EXPECT_EQ(HapSignerBlockUtils::FindEocdInHap(*outputHap, eocdPair), true);
    long long centralDirectoryOffset;
    EXPECT_EQ(HapSignerBlockUtils::GetCentralDirectoryOffset(eocdPair.first, eocdPair.second, centralDirectoryOffset),
        true);
    DataSource* beforeCentralDir = outputHapIn->Slice(0, centralDirectoryOffset);
    EXPECT_EQ(beforeCentralDir != nullptr, true);
}

/**
 * @tc.name: Test Slice Function
 * @tc.desc: Test function of RandomAccessFileInput::Slice() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileInputSliceTest002, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileInput>(*outputHap, 0, 10);
    DataSource* beforeCentralDir = outputHapIn->Slice(-1, 10);
    EXPECT_EQ(beforeCentralDir == nullptr, true);
}

/**
 * @tc.name: Test Slice Function
 * @tc.desc: Test function of RandomAccessFileInput::Slice() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileInputSliceTest003, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileInput>(*outputHap, 0, 10);
    DataSource* beforeCentralDir = outputHapIn->Slice(0, -1);
    EXPECT_EQ(beforeCentralDir == nullptr, true);
}

/**
 * @tc.name: Test Slice Function
 * @tc.desc: Test function of RandomAccessFileInput::Slice() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileInputSliceTest004, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileInput>(*outputHap, 0, 10);
    DataSource* beforeCentralDir = outputHapIn->Slice(20, 1);
    EXPECT_EQ(beforeCentralDir == nullptr, true);
}

/**
 * @tc.name: Test Slice Function
 * @tc.desc: Test function of RandomAccessFileInput::Slice() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileInputSliceTest005, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileInput>(*outputHap, 0, 10);
    DataSource* beforeCentralDir = outputHapIn->Slice(0, 20);
    EXPECT_EQ(beforeCentralDir == nullptr, true);
}

/**
 * @tc.name: Test CreateByteBuffer Function
 * @tc.desc: Test function of RandomAccessFileInput::CreateByteBuffer() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileInputCreateByteBufferTest001, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileInput>(*outputHap);
    std::pair<ByteBuffer, long long> eocdPair;
    EXPECT_EQ(HapSignerBlockUtils::FindEocdInHap(*outputHap, eocdPair), true);
    long long centralDirectoryOffset;
    EXPECT_EQ(HapSignerBlockUtils::GetCentralDirectoryOffset(eocdPair.first, eocdPair.second, centralDirectoryOffset),
        true);
    DataSource* beforeCentralDir = outputHapIn->Slice(0, centralDirectoryOffset);
    EXPECT_EQ(beforeCentralDir != nullptr, true);
    long centralDirectorySize;
    EXPECT_EQ(HapSignerBlockUtils::GetCentralDirectorySize(eocdPair.first, centralDirectorySize), true);
    ByteBuffer centralDirBuffer = outputHapIn->CreateByteBuffer(centralDirectoryOffset, centralDirectorySize);
    EXPECT_EQ(centralDirBuffer.GetCapacity() > 0, true);
}

/**
 * @tc.name: Test CreateByteBuffer Function
 * @tc.desc: Test function of RandomAccessFileInput::CreateByteBuffer() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileInputCreateByteBufferTest002, testing::ext::TestSize.Level1)
{
    std::string outputFile("/data/test/zip/signed.hap");
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileInput>(*outputHap);
    std::pair<ByteBuffer, long long> eocdPair;
    EXPECT_EQ(HapSignerBlockUtils::FindEocdInHap(*outputHap, eocdPair), true);
    ByteBuffer centralDirBuffer = outputHapIn->CreateByteBuffer(0, -1);
    EXPECT_EQ(centralDirBuffer.GetCapacity() == 0, true);
}

/**
 * @tc.name: Test Write ByteBuffer Function
 * @tc.desc: Test function of RandomAccessFileOutput::Write() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileOutputWriteTest001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    std::string outputFile("/data/test/zip/unsigned.hap");
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::pair<ByteBuffer, long long> eocdPair;
    EXPECT_EQ(HapSignerBlockUtils::FindEocdInHap(*outputHap, eocdPair), true);
    long long centralDirectoryOffset;
    EXPECT_EQ(HapSignerBlockUtils::GetCentralDirectoryOffset(eocdPair.first, eocdPair.second, centralDirectoryOffset),
        true);
    std::shared_ptr<RandomAccessFileOutput> outputHapOut =
        std::make_shared<RandomAccessFileOutput>(outputHap.get(), centralDirectoryOffset);
    ByteBuffer signingBlock(1);
    signingBlock.PutByte(1);
    EXPECT_EQ(outputHapOut->Write(signingBlock), true);
}

/**
 * @tc.name: Test Write ByteBuffer Function
 * @tc.desc: Test function of RandomAccessFileOutput::Write() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileOutputWriteTest002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    std::string outputFile("/data/test/zip/unsigned.hap");
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::pair<ByteBuffer, long long> eocdPair;
    EXPECT_EQ(HapSignerBlockUtils::FindEocdInHap(*outputHap, eocdPair), true);
    long long centralDirectoryOffset;
    EXPECT_EQ(HapSignerBlockUtils::GetCentralDirectoryOffset(eocdPair.first, eocdPair.second, centralDirectoryOffset),
        true);
    std::shared_ptr<RandomAccessFileOutput> outputHapOut =
        std::make_shared<RandomAccessFileOutput>(outputHap.get(), centralDirectoryOffset);
    ByteBuffer signingBlock;
    EXPECT_EQ(outputHapOut->Write(signingBlock), false);
}

/**
 * @tc.name: Test Write ByteBuffer Function
 * @tc.desc: Test function of RandomAccessFileOutput() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileOutputTest001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    std::string outputFile("/data/test/zip/unsigned.hap");
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<RandomAccessFileOutput> outputHapOut =
        std::make_shared<RandomAccessFileOutput>(outputHap.get());
    EXPECT_EQ(outputHapOut != nullptr, true);
}

/**
 * @tc.name: Test Write ByteBuffer Function
 * @tc.desc: Test function of RandomAccessFileOutput() interface for FAIL.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RandomAccessFileInputOutputTest, RandomAccessFileOutputTest002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    std::string outputFile("/data/test/zip/unsigned.hap");
    EXPECT_EQ(outputHap->Init(outputFile), true);
    std::shared_ptr<RandomAccessFileOutput> outputHapOut =
        std::make_shared<RandomAccessFileOutput>(outputHap.get(), -1);
    EXPECT_EQ(outputHapOut != nullptr, true);
}
} // namespace SignatureTools
} // namespace OHOS