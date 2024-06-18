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
#include <vector>
#include <gtest/gtest.h>
#include "code_sign_block.h"
#include "segment_header.h"
#include "hap_info_segment.h"
#include "sign_info.h"

using namespace OHOS::SignatureTools;

/*
* 测试套件,固定写法
*/
class CodeSignBlockTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: addOneMerkleTree001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, addOneMerkleTree001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    const std::string key;
    std::vector<int8_t> merkleTree;
    api->AddOneMerkleTree(key, merkleTree);  // 返回值void

    EXPECT_EQ(true, true);
}

/**
 * @tc.name: addOneMerkleTree002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, addOneMerkleTree002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    const std::string key = "111";
    std::vector<int8_t> merkleTree;
    api->AddOneMerkleTree(key, merkleTree);

    EXPECT_EQ(true, true);
}

/**
 * @tc.name: addToSegmentList
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, addToSegmentList, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
   
    SegmentHeader sh(SegmentHeader::CSB_NATIVE_LIB_INFO_SEG, 0);
    api->AddToSegmentList(sh);

    EXPECT_EQ(true, true);
}

/**
 * @tc.name: computeMerkleTreeOffset
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, computeMerkleTreeOffset, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
    
    long long codeSignBlockOffset = 949572;
    long long offset = api->ComputeMerkleTreeOffset(codeSignBlockOffset);

    EXPECT_NE(offset, 0);
}

/**
 * @tc.name: computeMerkleTreeOffset001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, computeMerkleTreeOffset001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    long long codeSignBlockOffset = -68;
    long long offset = api->ComputeMerkleTreeOffset(codeSignBlockOffset);

    EXPECT_EQ(offset, 0);
}

/**
 * @tc.name: computeSegmentOffset
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, computeSegmentOffset, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
    
    api->ComputeSegmentOffset();

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: getCodeSignBlockHeader
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, getCodeSignBlockHeader, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
    
    api->GetCodeSignBlockHeader();

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: getFsVerityInfoSegment
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, getFsVerityInfoSegment, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    api->GetFsVerityInfoSegment();

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: getHapInfoSegment
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, getHapInfoSegment, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    api->GetHapInfoSegment();

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: getOneMerkleTreeByFileName001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, getOneMerkleTreeByFileName001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    std::string key = "test.so";
    std::vector<int8_t> name = api->GetOneMerkleTreeByFileName(key);

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: getOneMerkleTreeByFileName002
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, getOneMerkleTreeByFileName002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    std::string key;
    std::vector<int8_t> name = api->GetOneMerkleTreeByFileName(key);
    int size = name.size();

    EXPECT_EQ(size, 0);
}

/**
 * @tc.name: getSegmentHeaderList
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, getSegmentHeaderList, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
   
    std::vector<SegmentHeader> segmentHeaderList = api->GetSegmentHeaderList();

    EXPECT_EQ(segmentHeaderList.size(), 0);
}

/**
 * @tc.name: getSoInfoSegment
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, getSoInfoSegment, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    api->GetSoInfoSegment();

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: setCodeSignBlockFlag
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, setCodeSignBlockFlag, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    api->SetCodeSignBlockFlag();

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: setCodeSignBlockFlag001
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, setCodeSignBlockFlag001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    NativeLibInfoSegment nativeLibInfoSegment(0,
    0,
    1,
    std::vector<SignedFilePos>(),
    std::vector<std::string>(),
    std::vector<SignInfo>(),
    std::vector<int8_t>());

    api->SetSoInfoSegment(nativeLibInfoSegment);
    api->SetCodeSignBlockFlag();

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: setCodeSignBlockHeader
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, setCodeSignBlockHeader, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    CodeSignBlockHeader::Builder* build = new CodeSignBlockHeader::Builder();
    build->SetBlockSize(4096);
    build->SetFlags(1);
    build->SetMagic(29);
    std::vector<int8_t> reservedVec(32, 1);
    build->SetReserved(reservedVec);
    build->SetSegmentNum(394);
    build->SetVersion(9);
    CodeSignBlockHeader codeSignBlockHeader(build);

    api->SetCodeSignBlockHeader(codeSignBlockHeader);

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: setFsVerityInfoSegment
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, setFsVerityInfoSegment, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
    
    FsVerityInfoSegment fsVeritySeg(1, 1, 12);

    api->SetFsVerityInfoSegment(fsVeritySeg);

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: setHapInfoSegment
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, setHapInfoSegment, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    int32_t saltSize = 0;
    int32_t flags = 1;
    int64_t dataSize = 5390336;
    std::vector<int8_t> salt;
    std::vector<int8_t> sig{ 48, -126, 7, -46, 6, 9, 42, -122, 72, -122, -9, 13, 1, 7,
        2, -96, -126, 7, -61, 48, -126, 7, -65, 2, 1, 1, 49, 13, 48, 11, 6, 9, 96, -122,
        72, 1, 101, 3, 4, 2, 1, 48, 11, 6, 9, 42, -122, 72, -122, -9, 13, 1, 7, 1, -96,
        -126, 6, 43, 48, -126, 1, -32, 48, -126, 1, -121, -96, 3, 2, 1, 2, 2, 4, 85, -67,
        -54, 116, 48, 10, 6, 8, 42, -122, 72, -50, 61, 4, 3, 3, 48, 85, 49, 11, 48, 9, 6,
        3, 85, 4, 6, 1 };
    SignInfo signInfo(saltSize, flags, dataSize, salt, sig);
    HapInfoSegment hapInfoSegment(10945, signInfo);
    api->SetHapInfoSegment(hapInfoSegment);

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: setSegmentHeaders
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, setSegmentHeaders, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
    
    api->SetSegmentHeaders();

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: setSegmentNum
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, setSegmentNum, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    api->SetSegmentNum();

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: setSoInfoSegment
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, setSoInfoSegment, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    int32_t magic = 248702752;
    int32_t segmentSize = 0;
    int32_t sectionNum = 0;
    std::vector<SignedFilePos> signedFilePosList;
    std::vector<std::string> fileNameList;
    std::vector<SignInfo> signInfoList;
    std::vector<int8_t> zeroPadding;

    NativeLibInfoSegment soSeg(magic, segmentSize, sectionNum, signedFilePosList,
        fileNameList, signInfoList, zeroPadding);
    api->SetSoInfoSegment(soSeg);

    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: toString
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(CodeSignBlockTest, toString, testing::ext::TestSize.Level1)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    std::string str = api->ToString();

    EXPECT_EQ(str.size(), 0);
}
