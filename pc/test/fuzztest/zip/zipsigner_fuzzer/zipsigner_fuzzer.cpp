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

#include "zip_signer.h"

using namespace OHOS::SignatureTools;
namespace OHOS {
static constexpr int ALIGNMENT = 4;

void ZipSignerCompleteFlowFunc(const uint8_t* data, size_t size)
{
    std::ifstream inputFile("./zip/test1.hap", std::ios::binary);
    std::ofstream outputFile("./zip/signed-test1.hap", std::ios::binary | std::ios::trunc);
    auto zip = std::make_shared<ZipSigner>();
    if (!zip->Init(inputFile)) {
        return;
    }
    zip->Alignment(ALIGNMENT);
    zip->RemoveSignBlock();
    zip->ToFile(inputFile, outputFile);
}

void SetZipSignerInfoFunc(const uint8_t* data, size_t size)
{
    std::ifstream inputFile("./zip/signed-test1.hap", std::ios::binary);
    auto zip = std::make_shared<ZipSigner>();
    if (!zip->Init(inputFile)) {
        return;
    }
    std::vector<ZipEntry*> zipEntries{ nullptr };
    zip->SetZipEntries(zipEntries);
    zip->SetSigningOffset(size);
    std::string signingBlock(reinterpret_cast<const char*>(data), size);
    zip->SetSigningBlock(signingBlock);
    zip->SetCDOffset(size);
    zip->SetEOCDOffset(size);
    zip->SetEndOfCentralDirectory(nullptr);
}

void GetZipSignerInfoFunc(const uint8_t* data, size_t size)
{
    std::ifstream inputFile("./zip/signed-test1.hap", std::ios::binary);
    auto zip = std::make_shared<ZipSigner>();
    if (!zip->Init(inputFile)) {
        return;
    }
    zip->GetZipEntries();
    zip->GetSigningOffset();
    zip->GetSigningBlock();
    zip->GetCDOffset();
    zip->GetEOCDOffset();
    zip->GetEndOfCentralDirectory();
}

void GetZipEntriesFunc(const uint8_t* data, size_t size)
{
    std::ifstream inputFile("./zip/unsigned_with_eocd.hap", std::ios::binary);
    auto zip = std::make_shared<ZipSigner>();
    zip->Init(inputFile);
}

void AlignmentFunc(const uint8_t* data, size_t size)
{
    std::ifstream inputFile("./zip/signed-test1.hap", std::ios::binary);
    auto zip = std::make_shared<ZipSigner>();
    if (!zip->Init(inputFile)) {
        return;
    }
    std::vector<ZipEntry*> zipEntries = zip->GetZipEntries();
    zipEntries[0]->Alignment(102400);
}



void DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    ZipSignerCompleteFlowFunc(data, size);
    SetZipSignerInfoFunc(data, size);
    GetZipEntriesFunc(data, size);
    AlignmentFunc(data, size);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}