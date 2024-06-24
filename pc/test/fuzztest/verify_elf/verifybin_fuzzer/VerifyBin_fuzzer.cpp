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
#include "verify_bin.h"
#include "sign_bin.h"
#include "hash_utils.h"
using namespace OHOS::SignatureTools;

#define SHA_224 5
#define SHA_256 6
#define VERSION 9
#define SHA_384 7
#define SHA_512 8

namespace OHOS {
static const std::map<std::string, std::string> PARAMS = {{"keyPwd", "123456"},
                                                           {"mode", "localSign"},
                                                           {"keyAlias", "oh-app1-key-v1"},
                                                           {"signAlg", "SHA256withECDSA"},
                                                           {"appCertFile", "./hapSign/app-release1.pem"},
                                                           {"signCode", "1"},
                                                           {"compatibleVersion", "9"},
                                                           {"keystorePwd", "123456"},
                                                           {"outFile", "./elfVerify/linuxout-signed.bin"},
                                                           {"profileSigned", "1"},
                                                           {"profileFile", "./hapSign/signed-profile.p7b"},
                                                           {"keystoreFile", "./hapSign/ohtest.jks"},
                                                           {"inFile", "./elfVerify/linuxout-unsigned.bin"}};

bool Verify001(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    return flag == true;
}

bool Verify002(const uint8_t* data, size_t size)
{
    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(nullptr);

    return flag == false;
}

bool Verify003(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.bin"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    return flag == false;
}

bool Verify004(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    return flag == false;
}

bool Verify005(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    return flag == false;
}

bool Verify006(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed111.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    return flag == false;
}

bool Verify007(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-unsigned.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    return flag == false;
}

bool Verify008(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/readonly.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    return flag == false;
}

bool Verify009(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    return flag == false;
}

bool Verify010(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err2.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    return flag == false;
}

bool Verify011(const uint8_t* data, size_t size)
{
    Options options;
    options.emplace(Options::IN_FILE, std::string("./elfVerify/linuxout-signed-err3.bin"));
    options.emplace(Options::OUT_CERT_CHAIN, std::string("./elfVerify/xx.cer"));
    options.emplace(Options::OUT_PROFILE, std::string("./elfVerify/xx.p7b"));

    VerifyBin verifyBin;
    bool flag = verifyBin.Verify(&options);

    return flag == false;
}

bool GetFileDigest001(const uint8_t* data, size_t size)
{
    std::string binFile = "./elfVerify/linuxout-signed.bin";
    SignBlockInfo signBlockInfo(true);
    VerifyElf::GetSignBlockInfo(binFile, signBlockInfo, VerifyElf::BIN_FILE_TYPE);
    std::vector<int8_t> signatrue = signBlockInfo.GetSignBlockMap().find(0)->second.GetValue();
    std::vector<int8_t> fileBytes;
    bool flag = VerifyElf::GetFileDigest(fileBytes, signatrue, signBlockInfo);

    return flag == false;
}

bool SignBin001(const uint8_t* data, size_t size)
{
    std::shared_ptr<SignBin> api = std::make_shared<SignBin>();
    std::map<std::string, std::string> signParams;
    signParams["a"] = "4";
    signParams["appCertFile"] = "./hapSign/app-release1.pem";
    signParams["compatibleVersion"] = "9";
    signParams["inFile"] = "./elfVerify/linuxout-unsigned.bin";
    signParams["inForm"] = "bin";
    signParams["keyAlias"] = "oh-app1-key-v1";
    signParams["keyPwd"] = "123456";
    signParams["keystoreFile"] = "./hapSign/ohtest.p12";
    signParams["keystorePwd"] = "123456";
    signParams["outFile"] = "./elfVerify/linuxout-signed.bin";
    signParams["profileFile"] = "./hapSign/signed-profile.p7b";
    signParams["profileSigned"] = "1";
    signParams["signAlg"] = "SHA256withECDSA";
    signParams["signCode"] = "1";
    int size = 32;
    SignerConfig signerConfig;
    signerConfig.SetCompatibleVersion(VERSION);
    signerConfig.FillParameters(PARAMS);

    ContentDigestAlgorithm contentDigestAlgorithm("SHA-256", size);
    std::pair<std::string, void*> signatureAlgAndParams("SHA256withECDSA", nullptr);
    SignatureAlgorithmHelper signatureAlgorithm(SignatureAlgorithmId::ECDSA_WITH_SHA256, "ECDSA_WITH_SHA256",
                                                contentDigestAlgorithm, signatureAlgAndParams);
    std::vector<SignatureAlgorithmHelper> signatureAlgorithms;
    signatureAlgorithms.push_back(signatureAlgorithm);
    signerConfig.SetSignatureAlgorithms(signatureAlgorithms);

    Options options;
    options.emplace("mode", std::string("localSign"));
    options.emplace("keyPwd", std::string("123456"));
    options.emplace("outFile", std::string("./elfVerify/linuxout-signed.bin"));
    options.emplace("keyAlias", std::string("oh-app1-key-v1"));
    options.emplace("profileFile", std::string("./hapSign/signed-profile.p7b"));
    options.emplace("signAlg", std::string("SHA256withECDSA"));
    options.emplace("keystorePwd", std::string("123456"));
    options.emplace("keystoreFile", std::string("./hapSign/ohtest.p12"));
    options.emplace("appCertFile", std::string("./hapSign/app-release1.pem"));
    options.emplace("inFile", std::string("./elfVerify/linuxout-unsigned.bin"));
    signerConfig.SetOptions(&options);
    bool flag = api->Sign(signerConfig, signParams);

    return flag == false;
}

bool GetHashAlgsId001(const uint8_t* data, size_t size)
{
    int algId = HashUtils::GetHashAlgsId("SHA-224");

    return algId == SHA_224;
}

bool GetHashAlgsId002(const uint8_t* data, size_t size)
{
    int algId = HashUtils::GetHashAlgsId("SHA-256");

    return algId == SHA_256;
}

bool GetHashAlgsId003(const uint8_t* data, size_t size)
{
    int algId = HashUtils::GetHashAlgsId("SHA-384");

    return algId == SHA_384;
}

bool GetHashAlgsId004(const uint8_t* data, size_t size)
{
    int algId = HashUtils::GetHashAlgsId("SHA-512");

    return algId == SHA_512;
}

bool GetHashAlgName001(const uint8_t* data, size_t size)
{
    std::string alg = HashUtils::GetHashAlgName(SHA_224);
    int sizet = alg.size();
    return sizet != 0;
}

bool GetHashAlgName002(const uint8_t* data, size_t size)
{
    std::string alg = HashUtils::GetHashAlgName(SHA_256);
    int sizet = alg.size();
    return sizet != 0;
}

bool GetHashAlgName003(const uint8_t* data, size_t size)
{
    std::string alg = HashUtils::GetHashAlgName(SHA_384);
    int sizet = alg.size();
    return sizet != 0;
}

bool GetHashAlgName004(const uint8_t* data, size_t size)
{
    std::string alg = HashUtils::GetHashAlgName(SHA_512);
    int sizet = alg.size();
    return sizet != 0;
}

bool GetDigestFromBytes001(const uint8_t* data, size_t size)
{
    std::vector<int8_t> fileBytes;
    int64_t length = 0;
    std::string algName = "SHA-256";
    std::vector<signed char> dig = HashUtils::GetDigestFromBytes(fileBytes, length, algName);
    int sizet = dig.size();
    return sizet == 0;
}

bool GetDigestFromBytes002(const uint8_t* data, size_t size)
{
    std::vector<int8_t> fileBytes = {1, 1};
    int64_t length = 0;
    std::string algName = "SHA-256";
    std::vector<signed char> dig = HashUtils::GetDigestFromBytes(fileBytes, length, algName);
    int sizet = dig.size();
    return sizet == 0;
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
    OHOS::GetFileDigest001(data, size);
    OHOS::SignBin001(data, size);
    OHOS::GetHashAlgsId001(data, size);
    OHOS::GetHashAlgsId002(data, size);
    OHOS::GetHashAlgsId003(data, size);
    OHOS::GetHashAlgsId004(data, size);
    OHOS::GetHashAlgName001(data, size);
    OHOS::GetHashAlgName002(data, size);
    OHOS::GetHashAlgName003(data, size);
    OHOS::GetHashAlgName004(data, size);
    OHOS::GetDigestFromBytes001(data, size);
    OHOS::GetDigestFromBytes002(data, size);
    return 0;
}