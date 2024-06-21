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
#include <fstream>
#include "verify_elf.h"
#include "hw_block_data.h"
#include "sign_provider.h"
#include "verify_hap.h"
using namespace OHOS::SignatureTools;

namespace OHOS {
bool Verify001(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    return flag == true;
}

bool Verify002(const uint8_t* data, size_t size)
{
    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(nullptr);

    return flag == false;
}

bool Verify003(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    return flag == false;
}

bool Verify004(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    return flag == false;
}

bool Verify005(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    return flag == false;
}

bool Verify006(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed111.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    return flag == false;
}

bool Verify007(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-unsigned.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    return flag == false;
}

bool Verify008(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/readonly.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    return flag == false;
}

bool Verify009(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    return flag == false;
}

bool Verify010(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err2.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    return flag == false;
}

bool Verify011(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err3.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    return flag == false;
}

bool Verify012(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err4.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyElf verifyElf;
    bool flag = verifyElf.Verify(&options);

    return flag == false;
}

bool CheckParams(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    bool flag = VerifyElf::CheckParams(&options);

    return flag == true;
}

bool CheckSignFile(const uint8_t* data, size_t size)
{
    std::string file = "./elfVerify/linuxout-signed.elf";

    bool flag = VerifyElf::CheckSignFile(file);

    return flag == true;
}

bool GetSignBlockData(const uint8_t* data, size_t size)
{
    std::vector<int8_t> bytes = { 1, 1, 1, 1, 1, 1, 1, 1 };
    HwBlockData hwBlockData(0, 0);

    bool flag = VerifyElf::GetSignBlockData(bytes, hwBlockData, "elf");

    return flag == false;
}

bool GetSignBlockInfo(const uint8_t* data, size_t size)
{
    std::string file = "./elfVerify/linuxout-signed.elf";
    SignBlockInfo signBlockInfo(false);

    bool flag = VerifyElf::GetSignBlockInfo(file, signBlockInfo, "elf");

    return flag == true;
}

bool GetFileDigest(const uint8_t* data, size_t size)
{
    std::string file = "./elfVerify/linuxout-signed.elf";
    SignBlockInfo signBlockInfo(false);
    VerifyElf::GetSignBlockInfo(file, signBlockInfo, "elf");
    std::vector<int8_t> fileBytes = { 1, 1, 1, 1, 1, 1, 1, 1 };
    std::vector<int8_t> signatrue = { 1, 1, 1, 1, 1, 1, 1, 1 };

    bool flag = VerifyElf::GetFileDigest(fileBytes, signatrue, signBlockInfo);

    return flag == false;
}

bool GetRawContent(const uint8_t* data, size_t size)
{
    std::vector<int8_t> contentVec = { 1, 1, 1, 1, 1, 1, 1, 1 };
    std::string rawContent;

    bool flag = VerifyElf::GetRawContent(contentVec, rawContent);

    return flag == false;
}

bool VerifyP7b(const uint8_t* data, size_t size)
{
    std::unordered_map<signed char, SigningBlock> signBlockMap;
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));
    Pkcs7Context pkcs7Context;
    HapVerifyResult verifyResult;
    std::string profileJson;

    bool flag = VerifyElf::VerifyP7b(signBlockMap, &options, pkcs7Context, verifyResult, profileJson);

    return flag == true;
}

bool SignElf001(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("signCode", std::string("1"));
    options.emplace("inForm", std::string("elf"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    return flag == true;
}

bool SignElf002(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("signCode", std::string("0"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    return flag == false;
}

bool SignElf003(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("signCode", std::string("2"));
    options.emplace("inForm", std::string("elf"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    return flag == false;
}

bool SignElf004(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/linuxout-unsigned"));
    options.emplace("signCode", std::string("1"));
    options.emplace("inForm", std::string("elf"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    return flag == false;
}

bool SignElf005(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux111.out"));
    options.emplace("signCode", std::string("1"));
    options.emplace("inForm", std::string("elf"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    return flag == false;
}

bool SignElf006(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA512withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("signCode", std::string("1"));
    options.emplace("inForm", std::string("elf"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    return flag == false;
}

bool SignElf007(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("signCode", std::string("1"));
    options.emplace("inForm", std::string("elf"));
    options.emplace("compatibleVersion", std::string("a"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    return flag == false;
}

bool SignElf008(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile111.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("signCode", std::string("1"));
    options.emplace("inForm", std::string("elf"));

    SignProvider signProvider;
    bool flag = signProvider.SignElf(&options);

    return flag == false;
}

bool SignBin001(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./hapSign/entry-default-signed.elf"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA512withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.jks"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./hapSign/unsigned-linux.out"));
    options.emplace("inForm", std::string("bin"));

    SignProvider signProvider;
    bool flag = signProvider.SignBin(&options);

    return flag == false;
}

bool VerifyElfProfile001(const uint8_t* data, size_t size)
{
    Options options;
    std::vector<int8_t> profileData = { 1, 1, 1, 1, 1, 1, 1, 1 };
    HapVerifyResult result;
    Pkcs7Context pkcs7Context;
    VerifyHap verifyHap;
    int32_t flag = verifyHap.VerifyElfProfile(profileData, result, &options, pkcs7Context);

    return flag != 0;
}

bool WriteVerifyOutput001(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    SignBlockInfo signBlockInfo(false);
    VerifyElf::GetSignBlockInfo("./elfVerify/linuxout-signed.elf", signBlockInfo, "elf");
    std::unordered_map<signed char, SigningBlock> signBlockMap = signBlockInfo.GetSignBlockMap();
    SigningBlock profileSign = signBlockMap.find(2)->second;
    std::vector<int8_t> profileByte = profileSign.GetValue();
    HapVerifyResult result;
    Pkcs7Context pkcs7Context;
    VerifyHap hapVerifyV2;
    hapVerifyV2.VerifyElfProfile(profileByte, result, &options, pkcs7Context);
    int32_t flag = hapVerifyV2.WriteVerifyOutput(pkcs7Context, &options);

    return flag != 0;
}

bool WriteVerifyOutput002(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.elf"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));

    SignBlockInfo signBlockInfo(false);
    VerifyElf::GetSignBlockInfo("./elfVerify/linuxout-signed.elf", signBlockInfo, "elf");
    std::unordered_map<signed char, SigningBlock> signBlockMap = signBlockInfo.GetSignBlockMap();
    SigningBlock profileSign = signBlockMap.find(2)->second;
    std::vector<int8_t> profileByte = profileSign.GetValue();
    HapVerifyResult result;
    Pkcs7Context pkcs7Context;
    VerifyHap hapVerifyV2;
    hapVerifyV2.VerifyElfProfile(profileByte, result, &options, pkcs7Context);
    int32_t flag = hapVerifyV2.WriteVerifyOutput(pkcs7Context, &options);

    return flag != 0;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Verify001(data, size);
    OHOS::Verify002(data, size);
    OHOS::Verify003(data, size);
    OHOS::Verify004(data, size);
    OHOS::Verify005(data, size);
    OHOS::Verify006(data, size);
    OHOS::Verify007(data, size);
    OHOS::Verify008(data, size);
    OHOS::Verify009(data, size);
    OHOS::Verify010(data, size);
    OHOS::Verify011(data, size);
    OHOS::Verify012(data, size);
    OHOS::CheckParams(data, size);
    OHOS::CheckSignFile(data, size);
    OHOS::GetSignBlockData(data, size);
    OHOS::GetFileDigest(data, size);
    OHOS::GetRawContent(data, size);
    OHOS::VerifyP7b(data, size);
    OHOS::SignElf001(data, size);
    OHOS::SignElf002(data, size);
    OHOS::SignElf003(data, size);
    OHOS::SignElf004(data, size);
    OHOS::SignElf005(data, size);
    OHOS::SignElf006(data, size);
    OHOS::SignElf007(data, size);
    OHOS::SignElf008(data, size);
    OHOS::SignBin001(data, size);
    OHOS::VerifyElfProfile001(data, size);
    OHOS::WriteVerifyOutput001(data, size);
    OHOS::WriteVerifyOutput002(data, size);
    return 0;
}