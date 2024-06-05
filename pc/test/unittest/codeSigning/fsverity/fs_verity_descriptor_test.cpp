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

#include <memory>
#include <gtest/gtest.h>
#include "fs_verity_descriptor.h"

using namespace OHOS::SignatureTools;

class FsVerityDescriptorTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: Build
 * @tc.desc: Test function of FsVerityDescriptor::Build() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FsVerityDescriptorTest, Build, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> salt = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();

    EXPECT_EQ(fsVerityDescriptor.GetFileSize(), 32);
}

/**
 * @tc.name: GetFileSize
 * @tc.desc: Test function of FsVerityDescriptor::GetFileSize() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FsVerityDescriptorTest, GetFileSize, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();

    EXPECT_EQ(fsVerityDescriptor.GetFileSize(), 32);
}

/**
 * @tc.name: GetMerkleTreeOffset
 * @tc.desc: Test function of FsVerityDescriptor::GetMerkleTreeOffset() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FsVerityDescriptorTest, GetMerkleTreeOffset, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();

    EXPECT_EQ(fsVerityDescriptor.GetMerkleTreeOffset(), 0);
}

/**
 * @tc.name: GetSignSize
 * @tc.desc: Test function of FsVerityDescriptor::GetSignSize() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FsVerityDescriptorTest, GetSignSize, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();

    EXPECT_EQ(fsVerityDescriptor.GetSignSize(), 32);
}

/**
 * @tc.name: ToByteArray
 * @tc.desc: Test function of FsVerityDescriptor::ToByteArray() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FsVerityDescriptorTest, ToByteArray, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();
    std::vector<int8_t> arr = fsVerityDescriptor.ToByteArray();

    EXPECT_EQ(fsVerityDescriptor.GetSignSize(), 32);
}

/**
 * @tc.name: FromByteArray
 * @tc.desc: Test function of FsVerityDescriptor::FromByteArray() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FsVerityDescriptorTest, FromByteArray, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();
    std::vector<int8_t> arr = fsVerityDescriptor.ToByteArray();
    FsVerityDescriptor fromArr = FsVerityDescriptor::FromByteArray(arr);

    EXPECT_EQ(fromArr.GetFileSize(), 32);
}

/**
 * @tc.name: GetByteForGenerateDigest
 * @tc.desc: Test function of FsVerityDescriptor::GetByteForGenerateDigest() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FsVerityDescriptorTest, GetByteForGenerateDigest, testing::ext::TestSize.Level1)
{
    std::vector<int8_t> salt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std::vector<int8_t> rootHash = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    FsVerityDescriptor::Builder builder = (new FsVerityDescriptor::Builder())->SetFileSize(32)
        .SetCsVersion(1)
        .SetHashAlgorithm(1)
        .SetLog2BlockSize(12)
        .SetSignSize((uint8_t)32)
        .SetSaltSize((uint8_t)32)
        .SetSalt(salt)
        .SetRawRootHash(rootHash)
        .SetFlags(1)
        .SetMerkleTreeOffset(0)
        .SetCsVersion(1);

    FsVerityDescriptor fsVerityDescriptor = builder.Build();
    std::vector<int8_t> bytes = fsVerityDescriptor.GetByteForGenerateDigest();

    EXPECT_EQ(fsVerityDescriptor.GetSignSize(), 32);
}