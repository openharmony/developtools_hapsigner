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

#include <gtest/gtest.h>
#include "signature_tools_log.h"
#include "options.h"
#include "sign_tool_service_impl.h"
#include "localization_adapter.h"
#include "openssl/ssl.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "p12_local.h"
#include "cmd_util.h"
#include "file_utils.h"
#include "params_run_tool.h"
#include "constant.h"
#include "params.h"
#include "params_trust_list.h"
#include "param_constants.h"

namespace OHOS {
namespace SignatureTools {

class HapSignToolCmdTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    };
    static void TearDownTestCase()
    {
    };
    void SetUp()
    {
    };
    void TearDown()
    {
    };
};

/*
 * @tc.name: hap_sign_tool_test_053
 * @tc.desc: Generate profile debugging certificate entry check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_053, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string keyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    std::string issuerKeyAlias = "oh-app-sign-srv-ca-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    int validity = 365;
    std::string signAlg = "SHA384withECDSA";
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
    char keystorePwd[] = "123456";
    std::string outFile = "./generateKeyPair/app-release1.pem";
    std::string subCaCertFile = "./generateKeyPair/app-sign-srv-ca1.txt";
    std::string outForm = "certChain";
    std::string rootCaCertFile = "./generateKeyPair/root-ca1.cer";

    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerKeyAlias;
    (*params)["subject"] = subject;
    (*params)["validity"] = validity;
    (*params)["signAlg"] = signAlg;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["outFile"] = outFile;
    (*params)["subCaCertFile"] = subCaCertFile;
    (*params)["outForm"] = outForm;
    (*params)["rootCaCertFile"] = rootCaCertFile;

    bool ret = ParamsRunTool::RunAppCert(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_054
 * @tc.desc: Generate profile debugging certificate entry check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_054, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string keyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    std::string issuerKeyAlias = "oh-app-sign-srv-ca-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    int validity = 365;
    std::string signAlg = "SHA384withECDSA";
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.txt";
    char keystorePwd[] = "123456";
    std::string outFile = "./generateKeyPair/app-release1.pem";
    std::string subCaCertFile = "./generateKeyPair/app-sign-srv-ca1.cer";
    std::string outForm = "certChain";
    std::string rootCaCertFile = "./generateKeyPair/root-ca1.cer";

    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerKeyAlias;
    (*params)["subject"] = subject;
    (*params)["validity"] = validity;
    (*params)["signAlg"] = signAlg;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["outFile"] = outFile;
    (*params)["subCaCertFile"] = subCaCertFile;
    (*params)["outForm"] = outForm;
    (*params)["rootCaCertFile"] = rootCaCertFile;

    bool ret = ParamsRunTool::RunAppCert(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_055
 * @tc.desc: Generate profile debugging certificate entry check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_055, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string keyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    std::string issuerKeyAlias = "oh-app-sign-srv-ca-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    int validity = 365;
    std::string signAlg = "SHA384withECDSA";
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
    char keystorePwd[] = "123456";
    std::string outFile = "./generateKeyPair/app-release1.pem";
    std::string subCaCertFile = "./generateKeyPair/app-sign-srv-ca1.cer";
    std::string outForm = "certChain";
    std::string rootCaCertFile = "./generateKeyPair/root-ca1.cer";
    std::string issuerKeystoreFile = "./generateKeyPair/OpenHarmony.txt";

    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerKeyAlias;
    (*params)["subject"] = subject;
    (*params)["validity"] = validity;
    (*params)["signAlg"] = signAlg;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["outFile"] = outFile;
    (*params)["subCaCertFile"] = subCaCertFile;
    (*params)["outForm"] = outForm;
    (*params)["rootCaCertFile"] = rootCaCertFile;
    (*params)["issuerKeystoreFile"] = issuerKeystoreFile;

    bool ret = ParamsRunTool::RunAppCert(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
* @tc.name: hap_sign_tool_test_056
* @tc.desc: Generate an app debug certificate for entry checks.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_056, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char keyPwd[] = "123456";
    std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    std::string issuerKeyAlias = "oh-profile-sign-srv-ca-key-v1";
    std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    int validity = 365;
    std::string signAlg = "SHA384withECDSA";
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
    char keystorePwd[] = "123456";
    std::string outFile = "./generateKeyPair/profile-release1.pem";
    std::string subCaCertFile = "./generateKeyPair/profile-sign-srv-ca1.cer";
    std::string outForm = "certChain";
    std::string rootCaCertFile = "./generateKeyPair/root-ca1.cer";

    (*params)["keyPwd"] = keyPwd;
    (*params)["issuer"] = issuer;
    (*params)["issuerKeyAlias"] = issuerKeyAlias;
    (*params)["subject"] = subject;
    (*params)["validity"] = validity;
    (*params)["signAlg"] = signAlg;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["outFile"] = outFile;
    (*params)["subCaCertFile"] = subCaCertFile;
    (*params)["outForm"] = outForm;
    (*params)["rootCaCertFile"] = rootCaCertFile;

    bool ret = ParamsRunTool::RunProfileCert(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_057
 * @tc.desc: Generates a key pair input check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_057, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 384;
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
    char keystorePwd[] = "123456";

    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = ParamsRunTool::RunKeypair(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_058
 * @tc.desc: Generates a key pair input check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_058, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string keyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "RSA";
    int keySize = 384;
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
    char keystorePwd[] = "123456";

    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = ParamsRunTool::RunKeypair(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_059
 * @tc.desc: Generates a key pair input check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_059, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string keyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 999;
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
    char keystorePwd[] = "123456";

    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = ParamsRunTool::RunKeypair(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_060
 * @tc.desc: Generates a key pair input check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_060, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string keyAlias = "oh-app1-key-v1";
    char keyPwd[] = "123456";
    std::string keyAlg = "ECC";
    int keySize = 384;
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.txt";
    char keystorePwd[] = "123456";

    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["keyAlg"] = keyAlg;
    (*params)["keySize"] = keySize;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = ParamsRunTool::RunKeypair(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: hap_sign_tool_test_061
 * @tc.desc: Test function of SignToolServiceImpl::RunCsr() interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, run_csr_test_061, testing::ext::TestSize.Level1)
{
    std::shared_ptr<SignToolServiceImpl> api = std::make_shared<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char keyPwd[] = "123456";
    char keystorePwd[] = "123456";

    (*params)["keyAlias"] = std::string("oh-app1-key-v1");
    (*params)["keyPwd"] = keyPwd;
    (*params)["subject"] = std::string("C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release");
    (*params)["keystoreFile"] = std::string("./generateKeyPair/OpenHarmony.p12");
    (*params)["keystorePwd"] = keystorePwd;

    bool ret = ParamsRunTool::RunCsr(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_062
 * @tc.desc: Generate a profile check-in check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_062, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string outFile = "./generateKeyPair/VerifyResult.json";
    (*params)["outFile"] = outFile;

    bool ret = ParamsRunTool::RunVerifyProfile(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_063
 * @tc.desc: Generate a profile check-in check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_063, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string inFile = "./generateKeyPair/signed-profile.txt";
    std::string outFile = "./generateKeyPair/VerifyResult.json";

    (*params)["inFile"] = inFile;
    (*params)["outFile"] = outFile;

    bool ret = ParamsRunTool::RunVerifyProfile(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_064
 * @tc.desc: Generate a profile check-in check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_064, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string inFile = "./generateKeyPair/signed-profile.p7b";
    std::string outFile = "./generateKeyPair/VerifyResult.txt";

    (*params)["inFile"] = inFile;
    (*params)["outFile"] = outFile;

    bool ret = ParamsRunTool::RunVerifyProfile(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_065
 * @tc.desc: Generate a profile check-in check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_065, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string outCertChain = "./generateKeyPair/app-sign-srv-ca1.cer";
    std::string outProfile = "./generateKeyPair/app-profile.p7b";

    (*params)["outCertChain"] = outCertChain;
    (*params)["outProfile"] = outProfile;

    bool ret = ParamsRunTool::RunVerifyApp(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_066
 * @tc.desc: Generate a profile check-in check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_066, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string inFile = "./generateKeyPair/entry-default-signed-so.hap";
    std::string outCertChain = "./generateKeyPair/app-sign-srv-ca1.cer";
    std::string outProfile = "./generateKeyPair/app-profile.txt";

    (*params)["inFile"] = inFile;
    (*params)["outCertChain"] = outCertChain;
    (*params)["outProfile"] = outProfile;

    bool ret = ParamsRunTool::RunVerifyApp(params.get(), *api);
    EXPECT_EQ(ret, false);
}

/*
* @tc.name: hap_sign_tool_test_067
* @tc.desc: Invoke the Generate generic certificate interface.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_067, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = " - validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-basicConstraintsPathLen";
    char arg23[] = "0";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: hap_sign_tool_test_068
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_068, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = " - validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-basicConstraintsPathLen";
    char arg23[] = "1000000000000000000000000000000000000000000000000000000";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_069
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_069, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = " - validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-validity";
    char arg23[] = "558g22";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_070
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_070, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-validity";
    char arg23[] = "558g2hhhsss1111111111111111111111111111111111112";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_071
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_071, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-keyUsageCritical";
    char arg23[] = "TRUE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: hap_sign_tool_test_072
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_072, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-keyUsageCritical";
    char arg23[] = "false";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: hap_sign_tool_test_073
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_073, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-keyUsageCritical";
    char arg23[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_074
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_074, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-extKeyUsageCritical";
    char arg23[] = "TRUE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;
    cmdUtil.Convert2Params(argv, argc, param);
    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_075
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_075, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-extKeyUsageCritical";
    char arg23[] = "FALSE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_076
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_076, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-extKeyUsageCritical";
    char arg23[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_077
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_077, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-basicConstraints";
    char arg23[] = "TRUE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_078
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_078, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-basicConstraints";
    char arg23[] = "FALSE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_079
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_079, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-basicConstraints";
    char arg23[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_080
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_080, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-basicConstraintsCritical";
    char arg23[] = "TRUE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_081
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_081, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-basicConstraintsCritical";
    char arg23[] = "FALSE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_082
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_082, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-basicConstraintsCritical";
    char arg23[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_083
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_083, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-basicConstraintsCa";
    char arg23[] = "TRUE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_084
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_084, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-basicConstraintsCa";
    char arg23[] = "FALSE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_085
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_085, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    char arg0[] = "";
    char arg1[] = "generate-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-profile-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA384withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-basicConstraintsCa";
    char arg23[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    ParamsSharedPtr param = std::make_shared<Params>();
    CmdUtil cmdUtil;

    cmdUtil.Convert2Params(argv, argc, param);

    bool ret = ParamsRunTool::DispatchParams(param, *api.get());
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_sign_tool_test_086
 * @tc.desc: Generate profile signature entry checks.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_086, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string keyAlias = "oh-profile1-key-v1";
    char keyPwd[] = "123456";
    std::string profileCertFile = "./generateKeyPair/profile-release1.pem";
    std::string inFile = "./generateKeyPair/profile.json";
    std::string signAlg = "SHA384withECDSA";
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
    char keystorePwd[] = "123456";
    std::string outFile = "./generateKeyPair/signed-profile.p7b";

    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["profileCertFile"] = profileCertFile;
    (*params)["inFile"] = inFile;
    (*params)["signAlg"] = signAlg;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["outFile"] = outFile;

    bool ret = ParamsRunTool::RunSignProfile(params.get(), *api);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: hap_sign_tool_test_087
 * @tc.desc: Generate profile signature entry checks.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_087, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "abcd";
    std::string keyAlias = "oh-profile1-key-v1";
    char keyPwd[] = "123456";
    std::string profileCertFile = "./generateKeyPair/profile-release1.pem";
    std::string inFile = "./generateKeyPair/profile.json";
    std::string signAlg = "SHA384withECDSA";
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
    char keystorePwd[] = "123456";
    std::string outFile = "./generateKeyPair/signed-profile.p7b";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["profileCertFile"] = profileCertFile;
    (*params)["inFile"] = inFile;
    (*params)["signAlg"] = signAlg;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["outFile"] = outFile;

    bool ret = ParamsRunTool::RunSignProfile(params.get(), *api);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: hap_sign_tool_test_088
 * @tc.desc: Generate profile signature entry checks.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_088, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-profile1-key-v1";
    char keyPwd[] = "123456";
    std::string profileCertFile = "./generateKeyPair/profile-release1.pem";
    std::string inFile = "./generateKeyPair/profile.json";
    std::string signAlg = "SHA384withECDSA";
    char keystorePwd[] = "123456";
    std::string outFile = "./generateKeyPair/signed-profile.p7b";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["profileCertFile"] = profileCertFile;
    (*params)["inFile"] = inFile;
    (*params)["signAlg"] = signAlg;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["outFile"] = outFile;

    bool ret = ParamsRunTool::RunSignProfile(params.get(), *api);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: hap_sign_tool_test_089
 * @tc.desc: Generate profile signature entry checks.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_089, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-profile1-key-v1";
    char keyPwd[] = "123456";
    std::string profileCertFile = "./generateKeyPair/profile-release1.pem";
    std::string inFile = "./generateKeyPair/profile.json";
    std::string signAlg = "SHA384withECDSA";
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.txt";
    char keystorePwd[] = "123456";
    std::string outFile = "./generateKeyPair/signed-profile.p7b";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["profileCertFile"] = profileCertFile;
    (*params)["inFile"] = inFile;
    (*params)["signAlg"] = signAlg;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["outFile"] = outFile;

    bool ret = ParamsRunTool::RunSignProfile(params.get(), *api);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: hap_sign_tool_test_090
 * @tc.desc: Generate profile signature entry checks.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_090, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-profile1-key-v1";
    char keyPwd[] = "123456";
    std::string profileCertFile = "./generateKeyPair/profile-release1.pem";
    std::string inFile = "./generateKeyPair/profile.json";
    std::string signAlg = "SHA384acd";
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
    char keystorePwd[] = "123456";
    std::string outFile = "./generateKeyPair/signed-profile.p7b";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["profileCertFile"] = profileCertFile;
    (*params)["inFile"] = inFile;
    (*params)["signAlg"] = signAlg;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["outFile"] = outFile;

    bool ret = ParamsRunTool::RunSignProfile(params.get(), *api);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: hap_sign_tool_test_091
 * @tc.desc: Generate profile signature entry checks.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_091, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "localSign";
    std::string keyAlias = "oh-profile1-key-v1";
    char keyPwd[] = "123456";
    std::string profileCertFile = "./generateKeyPair/profile-release1.pem";
    std::string inFile = "./generateKeyPair/profile.json";
    std::string signAlg = "SHA384withECDSA";
    std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
    char keystorePwd[] = "123456";
    std::string outFile = "./generateKeyPair/signed-profile.txt";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["keyPwd"] = keyPwd;
    (*params)["profileCertFile"] = profileCertFile;
    (*params)["inFile"] = inFile;
    (*params)["signAlg"] = signAlg;
    (*params)["keystoreFile"] = keystoreFile;
    (*params)["keystorePwd"] = keystorePwd;
    (*params)["outFile"] = outFile;

    bool ret = ParamsRunTool::RunSignProfile(params.get(), *api);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: hap_sign_tool_test_092
 * @tc.desc: Generate a profile check-in check.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapSignToolCmdTest, hap_sign_tool_test_092, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string inFile = "./generateKeyPair/entry-default-signed-so.hap";
    std::string outCertChain = "./generateKeyPair/app-sign-srv-ca1.cer";
    std::string outProfile = "./generateKeyPair/app-profile.p7b";
    std::string inform = "abcd";

    (*params)["inFile"] = inFile;
    (*params)["outCertChain"] = outCertChain;
    (*params)["outProfile"] = outProfile;
    (*params)["inForm"] = inform;

    bool ret = ParamsRunTool::RunVerifyApp(params.get(), *api);
    EXPECT_EQ(ret, true);
}
} // namespace SignatureTools
} // namespace OHOS