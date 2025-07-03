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

#include "verify_elf.h"

#include <fstream>
#include "constant.h"
#include "file_utils.h"
#include "signature_tools_log.h"
#include "verify_hap_openssl_utils.h"
#include "hash_utils.h"

namespace OHOS {
namespace SignatureTools {

const std::string VerifyElf::codesignSec = ".codesign";
const std::string VerifyElf::profileSec = ".profile";
const std::string VerifyElf::permissionSec = ".permission";

bool VerifyElf::Verify(Options* options)
{
    // check param
    if (options == nullptr) {
        PrintErrorNumberMsg("VERIFY_ERROR", VERIFY_ERROR, "Param options is null.");
        return false;
    }
    std::string elfFile = options->GetString(Options::IN_FILE);
    ELFIO::elfio elfReader;
    if (!elfReader.load(elfFile)) {
        SIGNATURE_TOOLS_LOGE("failed to load input ELF file");
        return false;
    }


    // get codesignSec section
    ParseSignBlock(elfReader);

    return true;
}

bool VerifyElf::ParseSignBlock(const ELFIO::elfio& elfReader)
{
    ELFIO::section* sec = elfReader.sections[codesignSec];
    if (!sec) {
        SIGNATURE_TOOLS_LOGE("codesign section is not found");
        return false;
    }
    ELFIO::Elf64_Off secOffElf64 = sec->get_offset();
    uint64_t secOff = static_cast<uint64_t>(secOffElf64);
    if (secOff % PAGE_SIZE != 0) {
        SIGNATURE_TOOLS_LOGE("codesign section offset is not aligned");
        return false;
    }
    const char* data = sec->get_data();
    uint64_t csBlockSize = sec->get_size();
    if (csBlockSize == 0 || csBlockSize % PAGE_SIZE != 0) {
        SIGNATURE_TOOLS_LOGE("codesign section size is not aligned");
        return false;
    }
    const ElfSignInfo* signInfo = reinterpret_cast<const ElfSignInfo*>(data);
    PrintMsg("codesign section offset: " + std::to_string(signInfo->dataSize));

    Pkcs7Context pkcs7Context;

    VerifyAppPkcs7(pkcs7Context, reinterpret_cast<const unsigned char*>(signInfo->signature), signInfo->signSize);

        if (!PrintCertChainToCmd(pkcs7Context.certChain[0])) {
            SIGNATURE_TOOLS_LOGE("print cert chain to cmd failed\n");
            return false;
        }

    return true;
}

bool VerifyElf::GetRawContent(const std::vector<int8_t>& contentVec, std::string& rawContent)
{
    PKCS7Data p7Data;
    int parseFlag = p7Data.Parse(contentVec);
    if (parseFlag < 0) {
        SIGNATURE_TOOLS_LOGE("parse content failed!");
        return false;
    }
    int verifyFlag = p7Data.Verify();
    if (verifyFlag < 0) {
        SIGNATURE_TOOLS_LOGE("verify content failed!");
        return false;
    }
    int getContentFlag = p7Data.GetContent(rawContent);
    if (getContentFlag < 0) {
        SIGNATURE_TOOLS_LOGE("get p7Data raw content failed!");
        return false;
    }
    return true;
}

bool VerifyElf::VerifyAppPkcs7(Pkcs7Context& pkcs7Context, const unsigned char* pkcs7Block, uint32_t pkcs7Len)
{
    // const unsigned char* pkcs7Block = reinterpret_cast<const unsigned char*>(hapSignatureBlock.GetBufferPtr());
    // uint32_t pkcs7Len = static_cast<unsigned int>(hapSignatureBlock.GetCapacity());
    if (!VerifyHapOpensslUtils::ParsePkcs7Package(pkcs7Block, pkcs7Len, pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("parse pkcs7 failed");
        return false;
    }
    if (!VerifyHapOpensslUtils::GetCertChains(pkcs7Context.p7, pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("GetCertChains from pkcs7 failed");
        return false;
    }
    if (!VerifyHapOpensslUtils::VerifyPkcs7(pkcs7Context)) {
        SIGNATURE_TOOLS_LOGE("verify signature failed");
        return false;
    }
    return true;
}

bool VerifyElf::PrintCertChainToCmd(std::vector<X509*>& certChain)
{
    BIO* outFd = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!outFd) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "The stdout stream may have errors");
        return false;
    }
    uint64_t format = XN_FLAG_SEP_COMMA_PLUS; // Print according to RFC2253
    uint64_t content = X509_FLAG_NO_EXTENSIONS | X509_FLAG_NO_ATTRIBUTES | X509_FLAG_NO_HEADER | X509_FLAG_NO_SIGDUMP;
    int num = 0;
    for (auto& cert : certChain) {
        PrintMsg("+++++++++++++++++++++++++++++++++certificate #" + std::to_string(num) +
                 "+++++++++++++++++++++++++++++++++++++");
        if (!X509_print_ex(outFd, cert, format, content)) {
            VerifyHapOpensslUtils::GetOpensslErrorMessage();
            SIGNATURE_TOOLS_LOGE("print x509 cert to cmd failed");
            BIO_free(outFd);
            return false;
        }
        ++num;
    }
    BIO_free(outFd);
    return true;
}

} // namespace SignatureTools
} // namespace OHOS