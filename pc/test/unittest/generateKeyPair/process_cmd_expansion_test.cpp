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

class ProcessCmdExpansionTest : public testing::Test {
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
 * @tc.name: processcmd_test_091
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_091, testing::ext::TestSize.Level1)
{
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
    char arg23[] = "true";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_092
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_092, testing::ext::TestSize.Level1)
{
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

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_093
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_093, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "sign-profile";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-mode";
    char arg7[] = "localSign";
    char arg8[] = "-signAlg";
    char arg9[] = "SHA384withECDSA";
    char arg10[] = "-inFile";
    char arg11[] = "./abcd/profile11.json";
    char arg12[] = "-keystoreFile";
    char arg13[] = "./generateKeyPair/OpenHarmony.p12";
    char arg14[] = "-keystorePwd";
    char arg15[] = "123456";
    char arg16[] = "-outFile";
    char arg17[] = "./generateKeyPair/signed-profile.p7b";
    char arg18[] = "-profileCertFile";
    char arg19[] = "./generateKeyPair/signed-profile.p7b";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19 };
    int argc = 20;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_094
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_094, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "generate-app-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-app1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-app-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "SHA256withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/app-release1.pem";
    char arg22[] = "-subCaCertFile";
    char arg23[] = "./generateKeyPair/app-sign-srv-ca1.cer";
    char arg24[] = "-outForm";
    char arg25[] = "certChain";
    char arg26[] = "-rootCaCertFile";
    char arg27[] = "./generateKeyPair/root-ca1.cer";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21,
                     arg22, arg23, arg24, arg25, arg26, arg27 };
    int argc = 28;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_095
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_095, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "generate-app-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-app1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-app-sign-srv-ca-key-v1";
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
    char arg21[] = "./generateKeyPair/app-release1.pem";
    char arg22[] = "-subCaCertFile";
    char arg23[] = "./generateKeyPair/app-sign-srv-ca1.cer";
    char arg24[] = "-outForm";
    char arg25[] = "certChain";
    char arg26[] = "-rootCaCertFile";
    char arg27[] = "./generateKeyPair/root-ca1.cer";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21,
                     arg22, arg23, arg24, arg25, arg26, arg27 };
    int argc = 28;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_096
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_096, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "generate-app-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-app1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-app-sign-srv-ca-key-v1";
    char arg10[] = "-subject";
    char arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
    char arg12[] = "-validity";
    char arg13[] = "365";
    char arg14[] = "-signAlg";
    char arg15[] = "abc";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/app-release1.pem";
    char arg22[] = "-subCaCertFile";
    char arg23[] = "./generateKeyPair/app-sign-srv-ca1.cer";
    char arg24[] = "-outForm";
    char arg25[] = "certChain";
    char arg26[] = "-rootCaCertFile";
    char arg27[] = "./generateKeyPair/root-ca1.cer";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21,
                     arg22, arg23, arg24, arg25, arg26, arg27 };
    int argc = 28;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_097
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_097, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "verify-app";
    char arg2[] = "-inFile";
    char arg3[] = "./generateKeyPair/entry-default-signed-so.hap";
    char arg4[] = "-outCertChain";
    char arg5[] = "./generateKeyPair/app-sign-srv-ca1.cer";
    char arg6[] = "-outProfile";
    char arg7[] = "./generateKeyPair/app-profile.p7b";
    char arg8[] = "-inForm";
    char arg9[] = "abc";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9 };
    int argc = 10;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_098
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_098, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "generate-app-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-app1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-app-sign-srv-ca-key-v1";
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
    char arg21[] = "./generateKeyPair/app-release1.pem";
    char arg22[] = "-subCaCertFile";
    char arg23[] = "./generateKeyPair/app-sign-srv-ca1.cer";
    char arg24[] = "-outForm";
    char arg25[] = "abcd";
    char arg26[] = "-rootCaCertFile";
    char arg27[] = "./generateKeyPair/root-ca1.cer";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21,
                     arg22, arg23, arg24, arg25, arg26, arg27 };
    int argc = 28;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_099
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_099, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "generate-profile-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-app1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-app-sign-srv-ca-key-v1";
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
    char arg21[] = "./generateKeyPair/app-release1.pem";
    char arg22[] = "-subCaCertFile";
    char arg23[] = "./generateKeyPair/app-sign-srv-ca1.cer";
    char arg24[] = "-outForm";
    char arg25[] = "abcd";
    char arg26[] = "-rootCaCertFile";
    char arg27[] = "./generateKeyPair/root-ca1.cer";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21,
                     arg22, arg23, arg24, arg25, arg26, arg27 };
    int argc = 28;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_100
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_100, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "generate-profile-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-app1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-app-sign-srv-ca-key-v1";
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
    char arg21[] = "./generateKeyPair/app-release1.pem";
    char arg22[] = "-subCaCertFile";
    char arg23[] = "./generateKeyPair/app-sign-srv-ca1.cer";
    char arg24[] = "-outForm";
    char arg25[] = "cert";
    char arg26[] = "-rootCaCertFile";
    char arg27[] = "./generateKeyPair/root-ca1.cer";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21,
                     arg22, arg23, arg24, arg25, arg26, arg27 };
    int argc = 28;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_101
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_101, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "generate-profile-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-app1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-app-sign-srv-ca-key-v1";
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
    char arg21[] = "./generateKeyPair/app-release1.pem";
    char arg22[] = "-subCaCertFile";
    char arg23[] = "./generateKeyPair/app-sign-srv-ca1.cer";
    char arg24[] = "-outForm";
    char arg25[] = "certChain";
    char arg26[] = "-rootCaCertFile";
    char arg27[] = "./generateKeyPair/root-ca1.cer";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21,
                     arg22, arg23, arg24, arg25, arg26, arg27 };
    int argc = 28;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_103
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_103, testing::ext::TestSize.Level1)
{
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
    char arg23[] = "1";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_104
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_104, testing::ext::TestSize.Level1)
{
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
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-keyUsageCritical";
    char arg23[] = "1";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 22;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_105
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_105, testing::ext::TestSize.Level1)
{
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
    char arg15[] = "SHA256withECDSA";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-keyUsageCritical";
    char arg23[] = "1";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_106
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_106, testing::ext::TestSize.Level1)
{
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
    char arg23[] = "1";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_107
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_107, testing::ext::TestSize.Level1)
{
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
    char arg15[] = "abcd";
    char arg16[] = "-keystoreFile";
    char arg17[] = "./generateKeyPair/OpenHarmony.p12";
    char arg18[] = "-keystorePwd";
    char arg19[] = "123456";
    char arg20[] = "-outFile";
    char arg21[] = "./generateKeyPair/general.cer";
    char arg22[] = "-keyUsageCritical";
    char arg23[] = "1";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_108
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_108, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "sign-app";
    char arg2[] = "-signAlg";
    char arg3[] = "SHA384withECDSA";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_109
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_109, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "verify-app";
    char arg2[] = "-signAlg";
    char arg3[] = "SHA384withECDSA";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_110
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_110, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "generate-app-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-app1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-app-sign-srv-ca-key-v1";
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
    char arg21[] = "./generateKeyPair/app-release1.pem";
    char arg22[] = "-subCaCertFile";
    char arg23[] = "./generateKeyPair/app-sign-srv-ca1.cer";
    char arg24[] = "-outForm";
    char arg25[] = "abcd";
    char arg26[] = "-rootCaCertFile";
    char arg27[] = "./generateKeyPair/root-ca1.cer";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21,
                     arg22, arg23, arg24, arg25, arg26, arg27 };
    int argc = 28;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_111
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_111, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "generate-profile-cert";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-app1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-issuer";
    char arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
    char arg8[] = "-issuerKeyAlias";
    char arg9[] = "oh-app-sign-srv-ca-key-v1";
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
    char arg21[] = "./generateKeyPair/app-release1.pem";
    char arg22[] = "-subCaCertFile";
    char arg23[] = "./generateKeyPair/app-sign-srv-ca1.cer";
    char arg24[] = "-outForm";
    char arg25[] = "abcd";
    char arg26[] = "-rootCaCertFile";
    char arg27[] = "./generateKeyPair/root-ca1.cer";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21,
                     arg22, arg23, arg24, arg25, arg26, arg27 };
    int argc = 28;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_112
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_112, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "sign-profile";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-mode";
    char arg7[] = "remoteSign";
    char arg8[] = "-signAlg";
    char arg9[] = "SHA384withECDSA";
    char arg10[] = "-inFile";
    char arg11[] = "./generateKeyPair/profile.json";
    char arg12[] = "-keystoreFile";
    char arg13[] = "./generateKeyPair/OpenHarmony.p12";
    char arg14[] = "-keystorePwd";
    char arg15[] = "123456";
    char arg16[] = "-outFile";
    char arg17[] = "./generateKeyPair/signed-profile.p7b";
    char arg18[] = "-profileCertFile";
    char arg19[] = "./generateKeyPair/signed-profile.p7b";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19 };
    int argc = 20;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_113
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_113, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "sign-profile";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg8[] = "-signAlg";
    char arg9[] = "SHA384withECDSA";
    char arg10[] = "-inFile";
    char arg11[] = "./generateKeyPair/profile.json";
    char arg12[] = "-keystoreFile";
    char arg13[] = "./generateKeyPair/OpenHarmony.p12";
    char arg14[] = "-keystorePwd";
    char arg15[] = "123456";
    char arg16[] = "-outFile";
    char arg17[] = "./generateKeyPair/signed-profile.p7b";
    char arg18[] = "-profileCertFile";
    char arg19[] = "./generateKeyPair/signed-profile.p7b";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19 };
    int argc = 18;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_114
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdExpansionTest, processcmd_test_114, testing::ext::TestSize.Level1)
{
    char arg0[] = "";
    char arg1[] = "sign-profile";
    char arg2[] = "-keyAlias";
    char arg3[] = "oh-profile1-key-v1";
    char arg4[] = "-keyPwd";
    char arg5[] = "123456";
    char arg6[] = "-mode";
    char arg7[] = "localSign";
    char arg8[] = "-signAlg";
    char arg9[] = "SHA384withECDSA";
    char arg10[] = "-inFile";
    char arg11[] = "./generateKeyPair/profile.json";
    char arg12[] = "-keystoreFile";
    char arg13[] = "./generateKeyPair/OpenHarmony.p12";
    char arg14[] = "-keystorePwd";
    char arg15[] = "123k456";
    char arg16[] = "-outFile";
    char arg17[] = "./generateKeyPair/signed-profile.p7b";
    char arg18[] = "-profileCertFile";
    char arg19[] = "./generateKeyPair/signed-profile.p7b";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19 };
    int argc = 20;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}
} // namespace SignatureTools
} // namespace OHOS