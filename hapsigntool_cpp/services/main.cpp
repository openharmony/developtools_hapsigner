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
#include <unistd.h>
#include <chrono>
#include <iomanip>
#include <cmath>
#include "signature_tools_log.h"
#include "params_run_tool.h"
using namespace OHOS::SignatureTools;

// 1.generate-keypair
void GenerateKeyPair()
{
    //std::string path = "./ohtest.p12";
    std::string path = "/data/local/tmp/ohtest.p12";
    static int64_t i = 1;
    SignToolServiceImpl api;

    // 1.delete p12 file��generate again
    remove(path.c_str());

    // 2.generate-keypair1
    Options options1;

    options1[Options::KEY_ALIAS] = std::string("oh-app1-key-v1");
    char keyPwd1[] = "123456";
    options1[Options::KEY_RIGHTS] = keyPwd1;
    options1[Options::KEY_ALG] = std::string("ECC");
    options1[Options::KEY_SIZE] = 256;
    options1[Options::KEY_STORE_FILE] = path;
    char keystorePwd1[] = "123456";
    options1[Options::KEY_STORE_RIGHTS] = keystorePwd1;
    bool result1 = api.GenerateKeyStore(&options1);
    PrintMsg("run GenerateKeyPair1() " + std::to_string(i) + " times,result1=" + std::to_string(result1));

    // 3.generate-keypair2
    Options options2;
    options2[Options::KEY_ALIAS] = std::string("oh-profile1-key-v1");
    char keyPwd2[] = "123456";
    options2[Options::KEY_RIGHTS] = keyPwd2;
    options2[Options::KEY_ALG] = std::string("ECC");
    options2[Options::KEY_SIZE] = 256;
    options2[Options::KEY_STORE_FILE] = path;
    char keystorePwd2[] = "123456";
    options2[Options::KEY_STORE_RIGHTS] = keystorePwd2;
    bool result2 = api.GenerateKeyStore(&options2);
    PrintMsg("run GenerateKeyPair2() " + std::to_string(i) + " times,result2=" + std::to_string(result2));
    ++i;
}

// 2.generate-csr
void GenerateCsr()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::KEY_ALIAS] = std::string("oh-app1-key-v1");
    char keyPwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyPwd;
    options[Options::SUBJECT] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release");
    options[Options::SIGN_ALG] = std::string("SHA256withECDSA");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    //options[Options::OUT_FILE] = std::string("./oh-app1-key-v1.csr");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/oh-app1-key-v1.csr");
    bool result = api.GenerateCsr(&options);
    PrintMsg("run GenerateCsr() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}

// 3.generate ca
// 3.1 generate root ca
void GenerateRootCa()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::KEY_ALIAS] = std::string("oh-root-ca-key-v1");
    options[Options::SUBJECT] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA");
    options[Options::VALIDITY] = 365;
    options[Options::SIGN_ALG] = std::string("SHA384withECDSA");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    //options[Options::OUT_FILE] = std::string("./root-ca1.cer");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/root-ca1.cer");
    options[Options::KEY_ALG] = std::string("ECC");
    options[Options::KEY_SIZE] = 256;
    bool result = api.GenerateCA(&options);
    PrintMsg("run GenerateRootCa() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}
// 3.2 generate app ca
void GenerateAppSubCa()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::KEY_ALIAS] = std::string("oh-app-sign-srv-ca-key-v1");
    options[Options::ISSUER] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA");
    options[Options::ISSUER_KEY_ALIAS] = std::string("oh-root-ca-key-v1");
    options[Options::SUBJECT] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Application Signature Service CA");
    options[Options::VALIDITY] = 365;
    options[Options::SIGN_ALG] = std::string("SHA384withECDSA");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    //options[Options::OUT_FILE] = std::string("./app-sign-srv-ca1.cer");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/app-sign-srv-ca1.cer");
    options[Options::KEY_ALG] = std::string("ECC");
    options[Options::KEY_SIZE] = 256;
    bool result = api.GenerateCA(&options);
    PrintMsg("run GenerateAppSubCa() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}
// 3.3 generate profile ca
void GenerateProfileSubCa()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::KEY_ALIAS] = std::string("oh-profile-sign-srv-ca-key-v1");
    options[Options::ISSUER] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA");
    options[Options::ISSUER_KEY_ALIAS] = std::string("oh-root-ca-key-v1");
    options[Options::SUBJECT] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Profile Signature Service CA");
    options[Options::VALIDITY] = 365;
    options[Options::SIGN_ALG] = std::string("SHA384withECDSA");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    //options[Options::OUT_FILE] = std::string("./profile-sign-srv-ca1.cer");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/profile-sign-srv-ca1.cer");
    options[Options::KEY_ALG] = std::string("ECC");
    options[Options::KEY_SIZE] = 384;
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    bool result = api.GenerateCA(&options);
    PrintMsg("run GenerateProfileSubCa() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}

// 4.generate cert
// 4.1 generate single root cert
void GenerateRootUniversalCer()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::KEY_ALIAS] = std::string("oh-app1-key-v1");
    options[Options::ISSUER] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA");
    options[Options::ISSUER_KEY_ALIAS] = std::string("oh-app1-key-v1");
    char issuerKeyPwd[] = "123456";
    options[Options::ISSUER_KEY_RIGHTS] = issuerKeyPwd;
    options[Options::SUBJECT] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA");
    options[Options::VALIDITY] = 365;
    options[Options::KEY_USAGE] = "certificateSignature";
    options[Options::SIGN_ALG] = std::string("SHA256withECDSA");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    //options[Options::OUT_FILE] = std::string("./single-root.cer");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/single-root.cer");
    char keyPwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyPwd;

    options[Options::KEY_USAGE_CRITICAL] = true;
    options[Options::EXT_KEY_USAGE_CRITICAL] = false;
    options[Options::BASIC_CONSTRAINTS] = false;
    options[Options::BASIC_CONSTRAINTS_CRITICAL] = false;
    options[Options::BASIC_CONSTRAINTS_CA] = false;
    bool result = api.GenerateCert(&options);
    PrintMsg("run GenerateRootUniversalCer() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}
// 4.2 generate single app cert
void GenerateAppUniversalCer()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::KEY_ALIAS] = std::string("oh-app1-key-v1");
    options[Options::ISSUER] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA");
    options[Options::ISSUER_KEY_ALIAS] = std::string("oh-app-sign-srv-ca-key-v1");
    options[Options::SUBJECT] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release");
    options[Options::VALIDITY] = 365;
    options[Options::KEY_USAGE] = "digitalSignature";
    options[Options::EXT_KEY_USAGE] = "codeSignature";
    options[Options::SIGN_ALG] = std::string("SHA256withECDSA");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    //options[Options::OUT_FILE] = std::string("./single-app1.cer");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/single-app1.cer");
    char keyPwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyPwd;

    options[Options::KEY_USAGE_CRITICAL] = true;
    options[Options::EXT_KEY_USAGE_CRITICAL] = false;
    options[Options::BASIC_CONSTRAINTS] = false;
    options[Options::BASIC_CONSTRAINTS_CRITICAL] = false;
    options[Options::BASIC_CONSTRAINTS_CA] = false;
    bool result = api.GenerateCert(&options);
    PrintMsg("run GenerateAppUniversalCer() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}

// 5.generate app cert
// 5.1 generate app cer
void GenerateAppDebugCer()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::KEY_ALIAS] = std::string("oh-app1-key-v1");
    options[Options::ISSUER] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA");
    options[Options::ISSUER_KEY_ALIAS] = std::string("oh-app-sign-srv-ca-key-v1");
    options[Options::SUBJECT] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release");
    options[Options::VALIDITY] = 365;
    options[Options::SIGN_ALG] = std::string("SHA256withECDSA");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    char keyPwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyPwd;
    //options[Options::OUT_FILE] = std::string("./app1.cer");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/app1.cer");
    options[Options::OUT_FORM] = std::string("cert");
    bool result = api.GenerateAppCert(&options);
    PrintMsg("run GenerateAppDebugCer() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}
// 5.2 generate app release
void GenerateAppReleaseCer()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::KEY_ALIAS] = std::string("oh-app1-key-v1");
    options[Options::ISSUER] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA");
    options[Options::ISSUER_KEY_ALIAS] = std::string("oh-app-sign-srv-ca-key-v1");
    options[Options::SUBJECT] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release");
    options[Options::VALIDITY] = 365;
    options[Options::SIGN_ALG] = std::string("SHA256withECDSA");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    //options[Options::OUT_FILE] = std::string("./app-release1.pem");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/app-release1.pem");
    //options[Options::SUB_CA_CERT_FILE] = std::string("./app-sign-srv-ca1.cer");
    options[Options::SUB_CA_CERT_FILE] = std::string("/data/local/tmp/app-sign-srv-ca1.cer");
    options[Options::OUT_FORM] = std::string("certChain");
    //options[Options::CA_CERT_FILE] = std::string("./root-ca1.cer");
    options[Options::CA_CERT_FILE] = std::string("/data/local/tmp/root-ca1.cer");
    char keyPwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyPwd;
    bool result = api.GenerateAppCert(&options);
    PrintMsg("run GenerateAppReleaseCer() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}

// 6.generate profile cert
// 6.1 generate profile debug cer
void GenerateProfileDebugCer()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::KEY_ALIAS] = std::string("oh-profile1-key-v1");
    options[Options::ISSUER] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA");
    options[Options::ISSUER_KEY_ALIAS] = std::string("oh-profile-sign-srv-ca-key-v1");
    options[Options::SUBJECT] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release");
    options[Options::VALIDITY] = 365;
    options[Options::SIGN_ALG] = std::string("SHA256withECDSA");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    //options[Options::OUT_FILE] = std::string("./profile1.cer");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/profile1.cer");
    char keyPwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyPwd;
    options[Options::OUT_FORM] = std::string("cert");
    bool result = api.GenerateProfileCert(&options);
    PrintMsg("run GenerateProfileDebugCer() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}
// generate profile release cer
void GenerateProfileReleaseCer()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::KEY_ALIAS] = std::string("oh-profile1-key-v1");
    options[Options::ISSUER] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile Signature Service CA");
    options[Options::ISSUER_KEY_ALIAS] = std::string("oh-profile-sign-srv-ca-key-v1");
    options[Options::SUBJECT] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Profile1 Release");
    options[Options::VALIDITY] = 365;
    options[Options::SIGN_ALG] = std::string("SHA256withECDSA");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    //options[Options::OUT_FILE] = std::string("./profile-release1.pem");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/profile-release1.pem");
    //options[Options::SUB_CA_CERT_FILE] = std::string("./profile-sign-srv-ca1.cer");
    options[Options::SUB_CA_CERT_FILE] = std::string("/data/local/tmp/profile-sign-srv-ca1.cer");
    options[Options::OUT_FORM] = std::string("certChain");
    //options[Options::CA_CERT_FILE] = std::string("./root-ca1.cer");
    options[Options::CA_CERT_FILE] = std::string("/data/local/tmp/root-ca1.cer");
    char keyPwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyPwd;
    bool result = api.GenerateProfileCert(&options);
    PrintMsg("run GenerateProfileReleaseCer() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}

// 7.sign-profile
void SignProfile()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::MODE] = std::string("localSign");
    options[Options::KEY_ALIAS] = std::string("oh-profile1-key-v1");
    //options[Options::PROFILE_CERT_FILE] = std::string("./profile-release1.pem");
    options[Options::PROFILE_CERT_FILE] = std::string("/data/local/tmp/profile-release1.pem");
    //options[Options::IN_FILE] = std::string("./profile.json");
    options[Options::IN_FILE] = std::string("/data/local/tmp/profile.json");
    options[Options::SIGN_ALG] = std::string("SHA256withECDSA");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    //options[Options::OUT_FILE] = std::string("./app1-profile1.p7b");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/app1-profile1.p7b");
    char keyPwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyPwd;
    bool result = api.SignProfile(&options);
    PrintMsg("run SignProfile() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}

// 8.verify-profile
void VerifyProfile()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    //options[Options::IN_FILE] = std::string("./app1-profile1.p7b");
    options[Options::IN_FILE] = std::string("/data/local/tmp/app1-profile1.p7b");
    bool result = api.VerifyProfile(&options);
    PrintMsg("run VerifyProfile() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}

// 9.sign-app
void SignZip()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::MODE] = std::string("localSign");
    options[Options::KEY_ALIAS] = std::string("oh-app1-key-v1");
    options[Options::SIGN_ALG] = std::string("SHA256withECDSA");
    //options[Options::APP_CERT_FILE] = std::string("./app-release1.pem");
    options[Options::APP_CERT_FILE] = std::string("/data/local/tmp/app-release1.pem");
    //options[Options::PROFILE_FILE] = std::string("./app1-profile1.p7b");
    options[Options::PROFILE_FILE] = std::string("/data/local/tmp/app1-profile1.p7b");
    //options[Options::IN_FILE] = std::string("./app1-unsigned.hap");
    options[Options::IN_FILE] = std::string("/data/local/tmp/app1-unsigned.hap");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    //options[Options::OUT_FILE] = std::string("./app1-signed.hap");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/app1-signed.hap");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    char keyPwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyPwd;
    options[Options::INFORM] = std::string("zip");
    bool result = api.SignHap(&options);
    PrintMsg("run SignZip() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}
void SignBin()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::MODE] = std::string("localSign");
    options[Options::KEY_ALIAS] = std::string("oh-app1-key-v1");
    options[Options::SIGN_ALG] = std::string("SHA256withECDSA");
    //options[Options::APP_CERT_FILE] = std::string("./app-release1.pem");
    options[Options::APP_CERT_FILE] = std::string("/data/local/tmp/app-release1.pem");
    //options[Options::PROFILE_FILE] = std::string("./app1-profile1.p7b");
    options[Options::PROFILE_FILE] = std::string("/data/local/tmp/app1-profile1.p7b");
    //options[Options::IN_FILE] = std::string("./unsigned-1M.bin");
    options[Options::IN_FILE] = std::string("/data/local/tmp/unsigned-1M.bin");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    //options[Options::OUT_FILE] = std::string("./signed-1M.bin");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/signed-1M.bin");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    char keyPwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyPwd;
    options[Options::INFORM] = std::string("bin");
    bool result = api.SignHap(&options);
    PrintMsg("run SignBin() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}
void SignElf()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    options[Options::MODE] = std::string("localSign");
    options[Options::KEY_ALIAS] = std::string("oh-app1-key-v1");
    options[Options::SIGN_ALG] = std::string("SHA256withECDSA");
    //options[Options::APP_CERT_FILE] = std::string("./app-release1.pem");
    options[Options::APP_CERT_FILE] = std::string("/data/local/tmp/app-release1.pem");
    //options[Options::PROFILE_FILE] = std::string("./app1-profile1.p7b");
    options[Options::PROFILE_FILE] = std::string("/data/local/tmp/app1-profile1.p7b");
    //options[Options::IN_FILE] = std::string("./unsigned-1M.elf");
    options[Options::IN_FILE] = std::string("/data/local/tmp/unsigned-1M.elf");
    //options[Options::KEY_STORE_FILE] = std::string("./ohtest.p12");
    options[Options::KEY_STORE_FILE] = std::string("/data/local/tmp/ohtest.p12");
    //options[Options::OUT_FILE] = std::string("./signed-1M.elf");
    options[Options::OUT_FILE] = std::string("/data/local/tmp/signed-1M.elf");
    char keystorePwd[] = "123456";
    options[Options::KEY_STORE_RIGHTS] = keystorePwd;
    char keyPwd[] = "123456";
    options[Options::KEY_RIGHTS] = keyPwd;
    options[Options::INFORM] = std::string("elf");
    bool result = api.SignHap(&options);
    PrintMsg("run SignElf() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}

//10.verify-app
void VerifyZip()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    //options[Options::IN_FILE] = std::string("./app1-signed.hap");
    options[Options::IN_FILE] = std::string("/data/local/tmp/app1-signed.hap");
    //options[Options::OUT_CERT_CHAIN] = std::string("./verify-zip.cer");
    options[Options::OUT_CERT_CHAIN] = std::string("/data/local/tmp/verify-zip.cer");
    //options[Options::OUT_PROFILE] = std::string("./verify-zip.p7b");
    options[Options::OUT_PROFILE] = std::string("/data/local/tmp/verify-zip.p7b");

    options[Options::INFORM] = std::string("zip");
    bool result = api.VerifyHapSigner(&options);
    PrintMsg("run VerifyZip() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}
void VerifyBin()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    //options[Options::IN_FILE] = std::string("./signed-1M.bin");
    options[Options::IN_FILE] = std::string("/data/local/tmp/signed-1M.bin");
    //options[Options::OUT_CERT_CHAIN] = std::string("./verify-bin.cer");
    options[Options::OUT_CERT_CHAIN] = std::string("/data/local/tmp/verify-bin.cer");
    //options[Options::OUT_PROFILE] = std::string("./verify-bin.p7b");
    options[Options::OUT_PROFILE] = std::string("/data/local/tmp/verify-bin.p7b");

    options[Options::INFORM] = std::string("bin");
    bool result = api.VerifyHapSigner(&options);
    PrintMsg("run VerifyBin() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}
void VerifyElf()
{
    static int64_t i = 1;
    SignToolServiceImpl api;
    Options options;
    //options[Options::IN_FILE] = std::string("./signed-1M.elf");
    options[Options::IN_FILE] = std::string("/data/local/tmp/signed-1M.elf");
    //options[Options::OUT_CERT_CHAIN] = std::string("./verify-elf.cer");
    options[Options::OUT_CERT_CHAIN] = std::string("/data/local/tmp/verify-elf.cer");
    //options[Options::OUT_PROFILE] = std::string("./verify-elf.p7b");
    options[Options::OUT_PROFILE] = std::string("/data/local/tmp/verify-elf.p7b");

    options[Options::INFORM] = std::string("elf");
    bool result = api.VerifyHapSigner(&options);
    PrintMsg("run VerifyElf() " + std::to_string(i) + " times,result=" + std::to_string(result));
    ++i;
}

void WholeFlow(bool recycle = false)
{
    /* 1.generate-keypair */
    GenerateKeyPair();

    /* 2.generate-csr */
    GenerateCsr();

    /* 3.generate ca */
    /* 3.1 generate root ca */
    GenerateRootCa();
    /* 3.2 generate app ca */
    GenerateAppSubCa();
    /* 3.3 generate profile ca */
    GenerateProfileSubCa();

    /* 4.generate - cert */
    /* 4.1 generate single root cert */
    GenerateRootUniversalCer();
    /* 4.2 generate single app cert */
    GenerateAppUniversalCer();

    /* 5.generate-app-cert */
    /* 5.1 generate app debug cer */
    GenerateAppDebugCer();
    /* 5.2 generate app release cer */
    GenerateAppReleaseCer();

    /* 6.generate-profile-cert */
    /* 6.1 generate profile debug cer */
    GenerateProfileDebugCer();
    /* 6.2 generate profile release cer */
    GenerateProfileReleaseCer();

    /* 7.sign-profile */
    SignProfile();

    /* 8.verify-profile */
    VerifyProfile();

    /* 9.sign-app */
    SignZip();
    SignBin();
    SignElf();

    /* 10.verify-app */
    VerifyZip();
    VerifyBin();
    VerifyElf();
}

enum class FlowCommand {
    GENERATE_KEYPAIR = 1,
    GENERATE_KEYPAIR_REPEAT = 10,
    GENERATE_CSR = 2,
    GENERATE_CSR_REPEAT = 20,
    GENERATE_ROOT_CA = 31,
    GENERATE_ROOT_CA_REPEAT = 310,
    GENERATE_APP_SUB_CA = 32,
    GENERATE_APP_SUB_CA_REPEAT = 320,
    GENERATE_PROFILE_SUB_CA = 33,
    GENERATE_PROFILE_SUB_CA_REPEAT = 330,
    GENERATE_ROOT_UNIVERSAL_CER = 41,
    GENERATE_ROOT_UNIVERSAL_CER_REPEAT = 410,
    GENERATE_APP_UNIVERSAL_CER = 42,
    GENERATE_APP_UNIVERSAL_CER_REPEAT = 420,
    GENERATE_APP_DEBUG_CER = 51,
    GENERATE_APP_DEBUG_CER_REPEAT = 510,
    GENERATE_APP_RELEASE_CER = 52,
    GENERATE_APP_RELEASE_CER_REPEAT = 520,
    GENERATE_PROFILE_DEBUG_CER = 61,
    GENERATE_PROFILE_DEBUG_CER_REPEAT = 610,
    GENERATE_PROFILE_RELEASE_CER = 62,
    GENERATE_PROFILE_RELEASE_CER_REPEAT = 620,
    SIGN_PROFILE = 7,
    SIGN_PROFILE_REPEAT = 70,
    VERIFY_PROFILE = 8,
    VERIFY_PROFILE_REPEAT = 80,
    SIGN_ZIP = 91,
    SIGN_ZIP_REPEAT = 910,
    SIGN_BIN = 92,
    SIGN_BIN_REPEAT = 920,
    SIGN_ELF = 93,
    SIGN_ELF_REPEAT = 930,
    VERIFY_ZIP = 101,
    VERIFY_ZIP_REPEAT = 1010,
    VERIFY_BIN = 102,
    VERIFY_BIN_REPEAT = 1020,
    VERIFY_ELF = 103,
    VERIFY_ELF_REPEAT = 1030,
    WHOLE_FLOW = 11,
    WHOLE_FLOW_REPEAT = 110,
    EXIT = 12,
};

void InterTest()
{
    do {
        std::cout << "******************** OpenHarmony Execute Flow Interface Test ********************" << std::endl;
        std::cout << "1 generate keypair" << std::endl;
        std::cout << "10 generate keypair repeat" << std::endl;
        std::cout << "2 generate csr" << std::endl;
        std::cout << "20 generate csr repeat" << std::endl;
        std::cout << "31 generate root ca" << std::endl;
        std::cout << "310 generate root ca repeat" << std::endl;
        std::cout << "32 generate app sub ca" << std::endl;
        std::cout << "320 generate app sub ca repeat" << std::endl;
        std::cout << "33 generate profile sub ca" << std::endl;
        std::cout << "330 generate profile sub ca repeat" << std::endl;
        std::cout << "41 generate root universal cer" << std::endl;
        std::cout << "410 generate root universal cer repeat" << std::endl;
        std::cout << "42 generate app universal cer" << std::endl;
        std::cout << "420 generate app universal cer repeat" << std::endl;
        std::cout << "51 generate app debug cer" << std::endl;
        std::cout << "510 generate app debug cer repeat" << std::endl;
        std::cout << "52 generate app release cer" << std::endl;
        std::cout << "520 generate app release cer repeat" << std::endl;
        std::cout << "61 generate profile debug cer" << std::endl;
        std::cout << "610 generate profile debug cer repeat" << std::endl;
        std::cout << "62 generate profile release cer" << std::endl;
        std::cout << "620 generate profile release cer repeat" << std::endl;
        std::cout << "7 sign profile" << std::endl;
        std::cout << "70 sign profile repeat" << std::endl;
        std::cout << "8 verify profile" << std::endl;
        std::cout << "80 verify profile repeat" << std::endl;
        std::cout << "91 sign zip" << std::endl;
        std::cout << "910 sign zip repeat" << std::endl;
        std::cout << "92 sign bin" << std::endl;
        std::cout << "920 sign bin repeat" << std::endl;
        std::cout << "93 sign elf" << std::endl;
        std::cout << "930 sign elf repeat" << std::endl;
        std::cout << "101 verify zip" << std::endl;
        std::cout << "1010 verify zip repeat" << std::endl;
        std::cout << "102 verify bin" << std::endl;
        std::cout << "1020 verify bin repeat" << std::endl;
        std::cout << "103 verify elf" << std::endl;
        std::cout << "1030 verify elf repeat" << std::endl;
        std::cout << "11:whole flow" << std::endl;
        std::cout << "110:whole flow repeat" << std::endl;
        std::cout << "12:exit" << std::endl;
        std::cout << "please select which flow to execute(example: input 1 run generate-keypair once,input 10 run generate-keypair repeat): " << std::endl;

        std::string str;
        getline(std::cin, str);
        FlowCommand flowCommand = static_cast<FlowCommand>(atoi(str.c_str()));

        switch (flowCommand) {
            case FlowCommand::GENERATE_KEYPAIR:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateKeyPair();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::GENERATE_KEYPAIR_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateKeyPair();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::GENERATE_CSR:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateCsr();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::GENERATE_CSR_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateCsr();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::GENERATE_ROOT_CA:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateRootCa();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::GENERATE_ROOT_CA_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateRootCa();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::GENERATE_APP_SUB_CA:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateAppSubCa();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::GENERATE_APP_SUB_CA_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateAppSubCa();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::GENERATE_PROFILE_SUB_CA:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateProfileSubCa();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::GENERATE_PROFILE_SUB_CA_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateProfileSubCa();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::GENERATE_ROOT_UNIVERSAL_CER:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateRootUniversalCer();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::GENERATE_ROOT_UNIVERSAL_CER_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateRootUniversalCer();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::GENERATE_APP_UNIVERSAL_CER:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateAppUniversalCer();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::GENERATE_APP_UNIVERSAL_CER_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateAppUniversalCer();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::GENERATE_APP_DEBUG_CER:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateAppDebugCer();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::GENERATE_APP_DEBUG_CER_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateAppDebugCer();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::GENERATE_APP_RELEASE_CER:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateAppReleaseCer();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::GENERATE_APP_RELEASE_CER_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateAppReleaseCer();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::GENERATE_PROFILE_DEBUG_CER:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateProfileDebugCer();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::GENERATE_PROFILE_DEBUG_CER_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateProfileDebugCer();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::GENERATE_PROFILE_RELEASE_CER:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateProfileReleaseCer();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::GENERATE_PROFILE_RELEASE_CER_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        GenerateProfileReleaseCer();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::SIGN_PROFILE:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        SignProfile();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::SIGN_PROFILE_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        SignProfile();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::VERIFY_PROFILE:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        VerifyProfile();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::VERIFY_PROFILE_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        VerifyProfile();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::SIGN_ZIP:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        SignZip();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::SIGN_ZIP_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        SignZip();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::SIGN_BIN:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        SignBin();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::SIGN_BIN_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        SignBin();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::SIGN_ELF:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        SignElf();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::SIGN_ELF_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        SignElf();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::VERIFY_ZIP:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        VerifyZip();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::VERIFY_ZIP_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        VerifyZip();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::VERIFY_BIN:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        VerifyBin();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::VERIFY_BIN_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        VerifyBin();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::VERIFY_ELF:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        VerifyElf();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::VERIFY_ELF_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        VerifyElf();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (true);
                }
                break;
            case FlowCommand::WHOLE_FLOW:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        WholeFlow();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("elapsed: " + std::to_string(elapsed.count()) + "s");
                    } while (0);
                }
                break;
            case FlowCommand::WHOLE_FLOW_REPEAT:
                {
                    auto start = std::chrono::steady_clock::now();
                    do {
                        WholeFlow();
                        auto end = std::chrono::steady_clock::now();
                        std::chrono::duration<double> elapsed = end - start;
                        PrintMsg("use time: " + std::to_string(elapsed.count()) + "s");
                        PrintMsg("run all function ok!");
                    } while (true);
                }
                break;
            case FlowCommand::EXIT:
                exit(0);
                break;
            default:
                std::cout << "select error,please try again: " << std::endl;
                break;
        }
    } while (true);
}

int main(int argc, char** argv)
{
    InterTest();

    // prepare modes vector by macro DEFINE_MODE which subscribe UPDATER_MAIN_PRE_EVENT event
    /*std::unique_ptr<ParamsRunTool> paramsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool isSuccess = paramsRunToolPtr->ProcessCmd(argv, argc);
    if (isSuccess) {
        return 0;
    } else {
        return -1;
    }*/
    return 0;
}