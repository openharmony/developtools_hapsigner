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

#include "hw_block_data.h"

using namespace OHOS::SignatureTools;

HwBlockData::HwBlockData(int32_t blockNum, int32_t blockStart)
{
    this->blockNum = blockNum;
    this->blockStart = blockStart;
}

int32_t HwBlockData::GetBlockNum()
{
    return blockNum;
}

void HwBlockData::SetBlockNum(int32_t blockNum)
{
    this->blockNum = blockNum;
}

int32_t HwBlockData::GetBlockStart()
{
    return blockStart;
}

void HwBlockData::SetBlockStart(int32_t blockStart)
{
    this->blockStart = blockStart;
}