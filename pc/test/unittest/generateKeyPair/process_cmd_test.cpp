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

class ProcessCmdTest : public testing::Test {
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
 * @tc.name: processcmd_test_001
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_001, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
        arg9[] = "NIST-P-384", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
        arg12[] = "-keystorePwd", arg13[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13 };

    int argc = 14;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_002
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_002, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "";
    char* argv[] = { arg0, arg1 };

    int argc = 2;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_003
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_003, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "-h";
    char* argv[] = { arg0, arg1 };

    int argc = 2;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_004
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_004, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "-v";
    char* argv[] = { arg0, arg1 };

    int argc = 2;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_005
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_005, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "";
    char* argv[] = { arg0, arg1, arg2, arg3 };

    int argc = 4;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_006
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_006, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "", arg3[] = "";
    char* argv[] = { arg0, arg1, arg2, arg3 };

    int argc = 4;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_008
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_008, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
        arg9[] = "NIST-P-385", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
        arg12[] = "-keystorePwd", arg13[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                     arg7, arg8, arg9, arg10, arg11, arg12, arg13 };

    int argc = 14;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    ParamsRunToolPtr->ProcessCmd(argv, argc);
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_012
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_012, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
        arg9[] = "NIST-P-256", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
        arg12[] = "-keystorePwd", arg13[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5,
                     arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13 };

    int argc = 14;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_013
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_013, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
        arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
        arg12[] = "-keystorePwd", arg13[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                     arg7, arg8, arg9, arg10, arg11, arg12, arg13 };

    int argc = 14;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_020
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_020, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
        arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
        arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-extKeyUsageCritical", arg15[] = "false";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                     arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

    int argc = 16;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_028
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_028, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias",
        arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA", arg12[] = "-keystoreFile",
        arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-keyUsageCritical", arg23[] = "true";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_029
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_029, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA", arg12[] = "-keystoreFile",
        arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-keyUsageCritical", arg23[] = "false";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_030
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_030, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA",
        arg12[] = "-keystoreFile", arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-keyUsageCritical", arg23[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_031
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_031, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA", arg12[] = "-keystoreFile",
        arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-extKeyUsageCritical", arg23[] = "true";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_032
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_032, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365", arg10[] = "-signAlg", arg11[] = "SHA384withECDSA",
        arg12[] = "-keystoreFile", arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-extKeyUsageCritical", arg23[] = "false";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_033
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_033, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA", arg12[] = "-keystoreFile",
        arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-extKeyUsageCritical", arg23[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_034
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_034, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA",
        arg12[] = "-keystoreFile", arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-basicConstraints", arg23[] = "true";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_035
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_035, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA", arg12[] = "-keystoreFile",
        arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-basicConstraints", arg23[] = "false";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_036
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_036, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA", arg12[] = "-keystoreFile",
        arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-basicConstraints", arg23[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_037
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_037, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA",
        arg12[] = "-keystoreFile", arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-basicConstraintsCritical", arg23[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_038
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_038, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA",
        arg12[] = "-keystoreFile", arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-basicConstraintsCritical", arg23[] = "true";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_039
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_039, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA", arg12[] = "-keystoreFile",
        arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-basicConstraintsCritical", arg23[] = "false";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_040
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_040, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA",
        arg12[] = "-keystoreFile", arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-basicConstraintsCa", arg23[] = "false";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_041
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_041, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA",
        arg12[] = "-keystoreFile", arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456",
        arg16[] = "-outFile", arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize",
        arg21[] = "NIST-P-384", arg22[] = "-basicConstraintsCa", arg23[] = "true";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_042
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_042, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
        arg8[] = "-validity", arg9[] = "365",
        arg10[] = "-signAlg", arg11[] = "SHA384withECDSA",
        arg12[] = "-keystoreFile", arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456",
        arg16[] = "-outFile", arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
        arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384",
        arg22[] = "-basicConstraintsCa", arg23[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_043
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_043, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer", arg22[] = "-keyPwd";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22 };
    int argc = 23;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_044
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_044, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
        arg9[] = "NIST-P-256", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
        arg12[] = "-keystorePwd", arg13[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13 };
    int argc = 14;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_045
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_045, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "/mnt/d/file/0613test/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "/mnt/d/file/0613test/general.cer",
        arg22[] = "-basicConstraintsPathLen", arg23[] = "0";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_046
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_046, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "sign-app", arg2[] = "-profileSigned", arg3[] = "1";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_047
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_047, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "sign-app", arg2[] = "-profileSigned", arg3[] = "true";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_048
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_048, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "sign-app", arg2[] = "-profileSigned", arg3[] = "TRUE";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_049
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_049, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "sign-app", arg2[] = "-profileSigned", arg3[] = "0";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_050
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_050, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "sign-app", arg2[] = "-profileSigned", arg3[] = "false";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_051
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_051, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "sign-app", arg2[] = "-profileSigned", arg3[] = "FALSE";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_052
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_052, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "sign-app", arg2[] = "-profileSigned", arg3[] = "abcd";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_053
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_053, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
        arg9[] = "NIST-P-256", arg10[] = "-keystoreFile", arg11[] = "./aabc123/OpenHarmony.p12",
        arg12[] = "-keystorePwd", arg13[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13 };
    int argc = 14;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_054
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_054, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
        arg9[] = "NIST-P-256", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair",
        arg12[] = "-keystorePwd", arg13[] = "123456";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13 };
    int argc = 14;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_055
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_055, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "sign-app", arg2[] = "-signAlg", arg3[] = "abcd";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_056
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_056, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "sign-app", arg2[] = "-signAlg", arg3[] = "SHA384withECDSA";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_057
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_057, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "verify-app", arg2[] = "-inForm", arg3[] = "abcd";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_058
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_058, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-app-cert", arg2[] = "-outForm", arg3[] = "abcd";
    char* argv[] = { arg0, arg1, arg2, arg3 };
    int argc = 4;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
* @tc.name: processcmd_test_059
* @tc.desc: main function entry function.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ProcessCmdTest, processcmd_test_059, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-app-cert";
    char* argv[] = { arg0, arg1 };
    int argc = 2;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: processcmd_test_063
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_063, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "-h";
    char* argv[] = { arg0, arg1 };
    int argc = 2;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_064
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_064, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "-help";
    char* argv[] = { arg0, arg1 };
    int argc = 2;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_065
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_065, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "-v";
    char* argv[] = { arg0, arg1 };
    int argc = 2;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_066
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_066, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "-version";
    char* argv[] = { arg0, arg1 };
    int argc = 2;
    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_067
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_067, testing::ext::TestSize.Level1)
{
    bool ret = ParamsRunTool::ProcessCmd(nullptr, 5);
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_079
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_079, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-keyUsageCritical", arg23[] = "TRUE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_080
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_080, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-keyUsageCritical", arg23[] = "true";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_081
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_081, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-extKeyUsageCritical", arg23[] = "1";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_082
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_082, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-extKeyUsageCritical", arg23[] = "true";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_083
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_083, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-extKeyUsageCritical", arg23[] = "TRUE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_084
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_084, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-basicConstraints", arg23[] = "TRUE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_085
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_085, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-basicConstraints", arg23[] = "1";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_086
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_086, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-basicConstraints", arg23[] = "true";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_087
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_087, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-basicConstraintsCritical", arg23[] = "true";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_088
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_088, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-basicConstraintsCritical", arg23[] = "TRUE";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_089
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_089, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-basicConstraintsCritical", arg23[] = "1";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_090
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_090, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-basicConstraintsCa", arg23[] = "1";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
    int argc = 24;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: processcmd_test_091
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProcessCmdTest, processcmd_test_091, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-basicConstraintsCa", arg23[] = "true";
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
HWTEST_F(ProcessCmdTest, processcmd_test_092, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
        arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
        arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
        arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
        arg12[] = "-validity", arg13[] = "365",
        arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
        arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
        arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
        arg22[] = "-basicConstraintsCa", arg23[] = "TRUE";
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
HWTEST_F(ProcessCmdTest, processcmd_test_093, testing::ext::TestSize.Level1)
{
    char arg0[] = "", arg1[] = "sign-profile", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
        arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-mode", arg7[] = "localSign",
        arg8[] = "-signAlg", arg9[] = "SHA384withECDSA",
        arg10[] = "-inFile", arg11[] = "./abcd/profile11.json", arg12[] = "-keystoreFile",
        arg13[] = "./generateKeyPair/OpenHarmony.p12",
        arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
        arg17[] = "./generateKeyPair/signed-profile.p7b", arg18[] = "-profileCertFile",
        arg19[] = "./generateKeyPair/signed-profile.p7b";
    char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                     arg13, arg14, arg15, arg16, arg17, arg18, arg19 };
    int argc = 20;

    std::unique_ptr<ParamsRunTool> ParamsRunToolPtr = std::make_unique<ParamsRunTool>();
    bool ret = ParamsRunToolPtr->ProcessCmd(argv, argc);

    EXPECT_EQ(ret, false);
}
} // namespace SignatureTools
} // namespace OHOS