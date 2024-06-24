/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include "code_sign_block.h"
#include "segment_header.h"
#include "hap_info_segment.h"
#include "sign_info.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool AddOneMerkleTree001(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    const std::string key;
    std::vector<int8_t> merkleTree;
    api->AddOneMerkleTree(key, merkleTree);  // 返回值void

    return true;
}

bool AddOneMerkleTree002(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    const std::string key = "111";
    std::vector<int8_t> merkleTree;
    api->AddOneMerkleTree(key, merkleTree);

    return true;
}

bool AddToSegmentList(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
   
    SegmentHeader sh(SegmentHeader::CSB_NATIVE_LIB_INFO_SEG, 0);
    api->AddToSegmentList(sh);

    return true;
}

bool ComputeMerkleTreeOffset001(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
    
    long long codeSignBlockOffset = 949572;
    api->ComputeMerkleTreeOffset(codeSignBlockOffset);

    return true;
}

bool ComputeMerkleTreeOffset002(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    long long codeSignBlockOffset = -68;
    long long offset = api->ComputeMerkleTreeOffset(codeSignBlockOffset);

    return offset == 0;
}

bool ComputeSegmentOffset(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
    
    api->ComputeSegmentOffset();

    return true;
}

bool GetCodeSignBlockHeader(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
    
    api->GetCodeSignBlockHeader();

    return true;
}

bool GetHapInfoSegment(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    api->GetHapInfoSegment();

    return true;
}

bool GetOneMerkleTreeByFileName001(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    std::string key = "test.so";
    std::vector<int8_t> name = api->GetOneMerkleTreeByFileName(key);

    return true;
}

bool GetOneMerkleTreeByFileName002(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    std::string key;
    std::vector<int8_t> name = api->GetOneMerkleTreeByFileName(key);
    int sizet = (int)name.size();

    return sizet == 0;
}

bool GetSegmentHeaderList(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
   
    std::vector<SegmentHeader> segmentHeaderList = api->GetSegmentHeaderList();

    return segmentHeaderList.size() == 0;
}

bool GetSoInfoSegment(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    api->GetSoInfoSegment();

    return true;
}

bool SetCodeSignBlockFlag001(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    api->SetCodeSignBlockFlag();

    return true;
}

bool SetCodeSignBlockFlag002(const uint8_t* data, size_t size)
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

    return true;
}

bool SetCodeSignBlockHeader(const uint8_t* data, size_t size)
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

    return true;
}

bool SetFsVerityInfoSegment(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
    
    FsVerityInfoSegment fsVeritySeg(1, 1, 12);

    api->SetFsVerityInfoSegment(fsVeritySeg);

    return true;
}

bool SetHapInfoSegment(const uint8_t* data, size_t size)
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

    return true;
}

bool SetSegmentHeaders(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();
    
    api->SetSegmentHeaders();

    return true;
}

bool SetSegmentNum(const uint8_t* data, size_t size)
{
    std::shared_ptr<CodeSignBlock> api = std::make_shared<CodeSignBlock>();

    api->SetSegmentNum();

    return true;
}

bool SetSoInfoSegment(const uint8_t* data, size_t size)
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

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AddOneMerkleTree001(data, size);
    OHOS::AddOneMerkleTree002(data, size);
    OHOS::AddToSegmentList(data, size);
    OHOS::ComputeMerkleTreeOffset001(data, size);
    OHOS::ComputeMerkleTreeOffset002(data, size);
    OHOS::ComputeSegmentOffset(data, size);
    OHOS::GetCodeSignBlockHeader(data, size);
    OHOS::GetHapInfoSegment(data, size);
    OHOS::GetOneMerkleTreeByFileName001(data, size);
    OHOS::GetOneMerkleTreeByFileName002(data, size);
    OHOS::GetSegmentHeaderList(data, size);
    OHOS::GetSoInfoSegment(data, size);
    OHOS::SetCodeSignBlockFlag001(data, size);
    OHOS::SetCodeSignBlockFlag002(data, size);
    OHOS::SetCodeSignBlockHeader(data, size);
    OHOS::SetFsVerityInfoSegment(data, size);
    OHOS::SetHapInfoSegment(data, size);
    OHOS::SetSegmentHeaders(data, size);
    OHOS::SetSegmentNum(data, size);
    OHOS::SetSoInfoSegment(data, size);
    return 0;
}