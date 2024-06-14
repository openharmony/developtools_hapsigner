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
#include "extension.h"

using namespace OHOS::SignatureTools;

 /*
 * 测试套件,固定写法
 */
class ExtensionTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: getSize
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ExtensionTest, getSize, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Extension> api = std::make_shared<Extension>();

    int32_t sizeInt = api->GetSize();

    EXPECT_NE(sizeInt, 0);
}

/**
 * @tc.name: isType
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ExtensionTest, isType, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Extension> api = std::make_shared<Extension>();

    int32_t type = 1;
    bool bIsType = api->IsType(type);

    EXPECT_EQ(bIsType, false);
}

/**
 * @tc.name: toByteArray
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ExtensionTest, toByteArray, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Extension> api = std::make_shared<Extension>();
   
    std::vector<int8_t> byteArray = api->ToByteArray();

    EXPECT_EQ(byteArray.size(), 8);
}

/**
 * @tc.name: toString
 * @tc.desc: Test function of SignToolServiceImpl::GenerateCsr() interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(ExtensionTest, toString, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Extension> api = std::make_shared<Extension>();

    std::string str = api->ToString();

    EXPECT_EQ(str.size(), 27);
}
