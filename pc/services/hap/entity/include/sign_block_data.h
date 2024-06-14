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

#ifndef SIGNATRUETOOLS_SIGN_BLOCK_DATA_H
#define SIGNATRUETOOLS_SIGN_BLOCK_DATA_H

#include <string>
#include <vector>

#include "file_utils.h"

namespace OHOS {
namespace SignatureTools {
class SignBlockData {
public:
    SignBlockData(std::vector<int8_t>& signData, char type);
    SignBlockData(std::string &signFile, char type);

    char GetType();
    void SetType(char type);
    std::vector<int8_t> GetBlockHead();
    void SetBlockHead(std::vector<int8_t> &blockHead);
    std::vector<int8_t> GetSignData();
    void SetSignData(std::vector<int8_t> &signData);
    std::string GetSignFile();
    void SetSignFile(std::string signFile);
    long GetLen();
    void SetLen(long len);
    void SetByte(bool isByte);
    bool GetByte();

private:
    char type;
    long len;
    bool isByte;
    std::vector<int8_t> blockHead;
    std::vector<int8_t> signData;
    std::string signFile;
};
} // namespace SignatureTools
} // namespace OHOS
#endif
