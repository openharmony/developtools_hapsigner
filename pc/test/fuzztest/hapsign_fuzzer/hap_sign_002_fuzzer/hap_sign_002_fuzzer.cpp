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
#include <memory>

#include "sign_tool_service_impl.h"
#include "options.h"
#include "local_sign_provider.h"
#include "sign_provider.h"

namespace OHOS {
namespace SignatureTools {
bool HapSignTest011(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    ContentDigestAlgorithm alg_tmp;
    ContentDigestAlgorithm alg_1 = ContentDigestAlgorithm::SHA256;
    ContentDigestAlgorithm* alg_2 = &alg_1;
    *alg_2 = alg_1;
    alg_tmp = alg_1;
    ContentDigestAlgorithm alg = ContentDigestAlgorithm::SHA256;
    std::string algname = alg.GetDigestAlgorithm();
    alg.GetDigestOutputByteSize();

    ContentDigestAlgorithm alg_384 = ContentDigestAlgorithm::SHA384;
    std::string algname_384 = alg_384.GetDigestAlgorithm();
    
    alg_384.GetDigestOutputByteSize();

    ContentDigestAlgorithm alg_512 = ContentDigestAlgorithm::SHA512;
    alg_512 = ContentDigestAlgorithm::SHA512;
    std::string algname_512 = alg_512.GetDigestAlgorithm();
    alg_512.GetDigestOutputByteSize();
    return true;
}

bool HapSignTest012(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    ByteBuffer bf1("123456789", 9); // key
    ByteBuffer bf2("123456789", 9);
    ByteBuffer bf3("123456789", 9);
    ByteBuffer bf4("123456789", 9);
    ByteBufferDataSource ds1(bf1);
    ByteBufferDataSource ds2(bf2);
    ByteBufferDataSource ds3(bf3);

    DataSource* contents[] = { &ds1, &ds2, &ds3 };
    int32_t len = 3;

    std::vector<OptionalBlock> optionalBlocks;
    optionalBlocks.push_back({ HapUtils::HAP_PROFILE_BLOCK_ID, bf4 });
    ByteBuffer dig_context;

    SignatureAlgorithm algo = SignatureAlgorithm::ALGORITHM_SHA256_WITH_ECDSA;
    int32_t nId = VerifyHapOpensslUtils::GetDigestAlgorithmId(algo);
    DigestParameter digestParam = HapSignerBlockUtils::GetDigestParameter(nId);

    return SignHap::ComputeDigests(digestParam, contents, len, optionalBlocks, dig_context);
}

bool HapSignTest013(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "1";
    std::string appCertFile = "./hapSign/app-release-nohave.pem"; // key
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string profileSigned = "1";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["profileSigned"] = profileSigned;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    (void)signProvider->GetCrl();
    

    return signProvider->Sign(params.get());
}

bool HapSignTest014(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "1";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string profileSigned = "1";
    std::string inFile = "./hapSign/nohave.hap"; // key
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["profileSigned"] = profileSigned;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    signProvider->CheckParams(params.get());

    return signProvider->Sign(params.get());
}

bool HapSignTest015(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "1";
    std::string appCertFile = "./hapSign/app-release-.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string profileSigned = "1";
    std::string inFile = "./hapSign/phone-default-unsigned.hap";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["profileSigned"] = profileSigned;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    signProvider->CheckParams(params.get());


    return signProvider->Sign(params.get());
}

bool HapSignTest016(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "1";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string profileSigned = "1";
    std::string inFile = "./hapSign/phone-default-unsigned.hap";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "/d/phone-default-signed.hap"; // key
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["profileSigned"] = profileSigned;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    return signProvider->Sign(params.get());
}

bool HapSignTest017(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "1";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string profileSigned = "1";
    std::string inFile = "./hapSign/phone-default-unsigned.hap";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-unsigned.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["profileSigned"] = profileSigned;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    signProvider->CheckParams(params.get());
    
    return signProvider->Sign(params.get());
}

bool HapSignTest018(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withEA"; // key
    std::string signCode = "1";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string profileSigned = "1";
    std::string inFile = "./hapSign/phone-default-unsigned.hap";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["profileSigned"] = profileSigned;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    return signProvider->Sign(params.get());
}

bool HapSignTest019(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1"; //key
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "0";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string inFile = "./hapSign/phone-default-unsigned";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    return signProvider->Sign(params.get());
}

bool HapSignTest020(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "0";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string inFile = "./hapSign/phone-default-unsigned"; // key
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    return signProvider->Sign(params.get());
}

bool HapSignTest021(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "0";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string inFile = "./hapSign/nohap.hap"; // key
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    return signProvider->Sign(params.get());
}

bool HapSignTest022(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignProvider> signProvider = std::make_unique<LocalSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "0";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string inFile = "./hapSign/unsigned_with_eocd.hap"; // key
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    return signProvider->Sign(params.get());
}

bool HapSignTest023(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "remoteSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "0";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string inFile = "./hapSign/phone-default-unsigned.hap";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    return api->SignHap(params.get());
}

bool HapSignTest024(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "remoteResign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "0";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string inFile = "./hapSign/phone-default-unsigned.hap";
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    return api->SignHap(params.get());
}

bool HapSignTest025(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "0";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string inFile = "./hapSign/phone-default-unsigned"; //key
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    return api->SignHap(params.get());
}

bool HapSignTest026(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    ByteBuffer bf1("123456789", 9); //key
    ByteBuffer bf2("123456789", 9);
    ByteBuffer bf3("123456789", 9);
    ByteBuffer bf4("123456789", 9);
    ByteBufferDataSource ds1(bf1);
    ByteBufferDataSource ds2(bf2);
    ByteBufferDataSource ds3(bf3);

    DataSource* contents[] = { &ds1, &ds2, &ds3 };
    DataSource* contents_t[] = { nullptr, nullptr, nullptr };
    int32_t len = 3;

    std::vector<OptionalBlock> optionalBlocks;
    std::vector<OptionalBlock> optionalBlockSTest;
    optionalBlocks.push_back({ HapUtils::HAP_PROFILE_BLOCK_ID, bf4 });
    ByteBuffer dig_context;

    SignatureAlgorithm algo = SignatureAlgorithm::ALGORITHM_SHA256_WITH_ECDSA;
    int32_t nId = VerifyHapOpensslUtils::GetDigestAlgorithmId(algo);
    DigestParameter digestParam = HapSignerBlockUtils::GetDigestParameter(nId);

    SignerConfig config;
    ByteBuffer result;
    ByteBuffer result1;
    (void)SignHap::Sign(contents, 2, config, optionalBlocks, result);
    

    (void)SignHap::Sign(contents_t, 3, config, optionalBlocks, result1);
    

    std::vector<SignatureAlgorithmHelper> sig{ SignatureAlgorithmHelper::ECDSA_WITH_SHA256_INSTANCE };
    config.SetSignatureAlgorithms(sig);
    (void)SignHap::Sign(contents_t, 3, config, optionalBlocks, result1);
    
    (void)SignHap::ComputeDigests(digestParam, contents, len, optionalBlockSTest, dig_context);
    return SignHap::ComputeDigests(digestParam, contents_t, len, optionalBlocks, dig_context);
}

bool HapSignTest027(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "0";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string inFile = "./hapSign/phone-default.hap"; // key
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    return api->SignHap(params.get());
}

bool HapSignTest028(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "0";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string inFile = "./hapSign/unsigned_with_cd_and_eocd.hap"; //key
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    return api->SignHap(params.get());
}

bool HapSignTest029(const uint8_t* data, size_t size)
{
    if (!data || !size) {
        return true;
    }
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string signAlg = "SHA256w"; // key
    std::string signCode = "0";
    std::string appCertFile = "./hapSign/app-release1.pem";
    std::string profileFile = "./hapSign/signed-profile.p7b";
    std::string inFile = "./hapSign/unsigned_with_cd_and_eocd.hap"; // key
    std::string keystoreFile = "./hapSign/ohtest.p12";
    std::string outFile = "./hapSign/phone-default-signed.hap";
    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["appCertFile"] = appCertFile;
    (*params)["profileFile"] = profileFile;
    (*params)["inFile"] = inFile;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["outFile"] = outFile;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keystorePwd"] = keystorePwd;

    return api->SignHap(params.get());
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SignatureTools::HapSignTest011(data, size);
    OHOS::SignatureTools::HapSignTest012(data, size);
    OHOS::SignatureTools::HapSignTest013(data, size);
    OHOS::SignatureTools::HapSignTest014(data, size);
    OHOS::SignatureTools::HapSignTest015(data, size);
    OHOS::SignatureTools::HapSignTest016(data, size);
    OHOS::SignatureTools::HapSignTest017(data, size);
    OHOS::SignatureTools::HapSignTest018(data, size);
    OHOS::SignatureTools::HapSignTest019(data, size);
    OHOS::SignatureTools::HapSignTest020(data, size);
    OHOS::SignatureTools::HapSignTest021(data, size);
    OHOS::SignatureTools::HapSignTest022(data, size);
    OHOS::SignatureTools::HapSignTest023(data, size);
    OHOS::SignatureTools::HapSignTest024(data, size);
    OHOS::SignatureTools::HapSignTest025(data, size);
    OHOS::SignatureTools::HapSignTest026(data, size);
    OHOS::SignatureTools::HapSignTest027(data, size);
    OHOS::SignatureTools::HapSignTest028(data, size);
    OHOS::SignatureTools::HapSignTest029(data, size);
    return 0;
}


