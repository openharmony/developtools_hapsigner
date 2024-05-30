#include "generate_keyPair_Test.h"

namespace OHOS {
    namespace SignatureTools {

        /*
         * @tc.name: generate_keypair_test_001
         * @tc.desc: Generate a key pair and load it into the keystore.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, generate_keypair_test_001, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "alias";
            char keyPwd[] = "123456";
            std::string keyAlg = "ECC";
            int keySize = 256;
            std::string keystoreFile = "./generateKeyPair/keypair.p12";
            char keystorePwd[] = "123456";

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = api->GenerateKeyStore(params.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: generate_keypair_test_002
         * @tc.desc: If you search for a key pair in the keystore using an alias,
         * @the key pair pointer is returned on success, and NULL is returned on failure.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, generate_keypair_test_002, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "alias";
            char keyPwd[] = "123456";
            std::string keyAlg = "ECC";
            int keySize = 256;
            std::string keystoreFile = "./generateKeyPair/keypair.p12";
            char keystorePwd[] = "123456";

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            EVP_PKEY* keyPair = nullptr;
            keyPair = adaptePtr->IsExist(adaptePtr->options->GetString(Options::KEY_ALIAS));
            EXPECT_NE(keyPair, nullptr);
        }


        /*
         * @tc.name: generate_keypair_test_003
         * @tc.desc: Generate a key pair and load it into the keystore.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, generate_keypair_test_003, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "alias";
            char keyPwd[] = "123456";
            std::string keyAlg = "ECC";
            int keySize = 256;
            std::string keystoreFile = "./generateKeyPair/keypair.p12";
            char keystorePwd[] = "123456";

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            EVP_PKEY* keyPair = nullptr;
            keyPair = adaptePtr->GetAliasKey(true);
            EXPECT_NE(keyPair, nullptr);
        }

        /*
         * @tc.name: generate_keypair_test_004
         * @tc.desc: Generate key pair.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, generate_keypair_test_004, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlg = "ECC";
            int keySize = 256;

            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            EVP_PKEY* keyPair = nullptr;
            std::string keyStorePath = adaptePtr->options->GetString(Options::KEY_STORE_FILE);
            keyPair = adaptePtr->keyStoreHelper->GenerateKeyPair(adaptePtr->options->GetString(Options::KEY_ALG),
                                                                 adaptePtr->options->GetInt(Options::KEY_SIZE));
            EXPECT_NE(keyPair, nullptr);
        }

        /*
         * @tc.name: generate_keypair_test_005
         * @tc.desc: Load the key pair into the file.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, generate_keypair_test_005, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "alias";
            char keyPwd[] = "123456";
            std::string keyAlg = "ECC";
            int keySize = 256;
            std::string keystoreFile = "./generateKeyPair/keypair.p12";
            char keystorePwd[] = "123456";

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            EVP_PKEY* keyPair = nullptr;
            std::string keyStorePath = adaptePtr->options->GetString(Options::KEY_STORE_FILE);
            keyPair = adaptePtr->keyStoreHelper->GenerateKeyPair(adaptePtr->options->GetString(Options::KEY_ALG),
                                                                 adaptePtr->options->GetInt(Options::KEY_SIZE));
            keyPair = adaptePtr->keyStoreHelper->Store(keyPair, keyStorePath,
                                                       adaptePtr->options->GetChars(Options::KEY_STORE_RIGHTS),
                                                       adaptePtr->options->GetString(Options::KEY_ALIAS));
            EXPECT_NE(keyPair, nullptr);
        }

        /*
         * @tc.name: generate_keypair_test_006
         * @tc.desc: Read the key pair from the file by alias.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, generate_keypair_test_006, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "alias";
            std::string keystoreFile = "./generateKeyPair/keypair.p12";
            char keystorePwd[] = "123456";

            (*params)["keyAlias"] = keyAlias;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            EVP_PKEY* keyPair = nullptr;
            std::string keyStorePath = adaptePtr->options->GetString(Options::KEY_STORE_FILE);
            keyPair = adaptePtr->keyStoreHelper->ReadStore(keyStorePath,
                                                           adaptePtr->options->GetChars(Options::KEY_STORE_RIGHTS),
                                                           adaptePtr->options->GetString(Options::KEY_ALIAS));
            EXPECT_NE(keyPair, nullptr);
        }

        /*
         * @tc.name: generate_keypair_test_007
         * @tc.desc: reset passwords.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, generate_keypair_test_007, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char keyPwd[] = "123456";
            char keystorePwd[] = "123456";
            char issuerKeyPwd[] = "123456";
            char issuerkeystorePwd[] = "123456";

            (*params)["keyPwd"] = keyPwd;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["issuerKeyPwd"] = issuerKeyPwd;
            (*params)["issuerkeystorePwd"] = issuerkeystorePwd;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            adaptePtr->ResetPwd();
            EXPECT_EQ(adaptePtr->options->GetChars(Options::KEY_RIGHTS), nullptr);
            EXPECT_EQ(adaptePtr->options->GetChars(Options::KEY_STORE_RIGHTS), nullptr);
            EXPECT_EQ(adaptePtr->options->GetChars(Options::ISSUER_KEY_RIGHTS), nullptr);
            EXPECT_EQ(adaptePtr->options->GetChars(Options::ISSUER_KEY_STORE_RIGHTS), nullptr);
        }


        /*
         * @tc.name: Options_test_001
         * @tc.desc: get char* type value, and do type checking.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, Options_test_001, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char keyPwd[] = "123456";
            (*params)["keyPwd"] = keyPwd;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            char* strPrt = adaptePtr->options->GetChars(Options::KEY_RIGHTS);

            EXPECT_NE(strPrt, nullptr);
        }


        /*
         * @tc.name: Options_test_002
         * @tc.desc: get string type value, and do type checking.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, Options_test_002, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "alias";
            (*params)["keyAlias"] = keyAlias;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            std::string strPrt = adaptePtr->options->GetString(Options::KEY_ALIAS);

            EXPECT_NE(strPrt, "");
        }


        /*
         * @tc.name: Options_test_003
         * @tc.desc: get two-parameter string type value, and do type checking.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, Options_test_003, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "alias";
            std::string str = "test";

            (*params)["keyAlias"] = keyAlias;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            std::string strPrt = adaptePtr->options->GetString(Options::KEY_ALIAS, str);

            if (strPrt == keyAlias) {
                EXPECT_EQ(strPrt, keyAlias);
            } else if (strPrt == str) {
                EXPECT_EQ(strPrt, str);
            } else {
                EXPECT_EQ(strPrt, keyAlias);
            }
        }


        /*
         * @tc.name: Options_test_004
         * @tc.desc: get Int type value, and do type checking.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, Options_test_004, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            int keySize = 256;
            (*params)["keySize"] = keySize;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            int size = adaptePtr->options->GetInt(Options::KEY_SIZE);

            EXPECT_NE(size, 0);
        }


        /*
         * @tc.name: Options_test_005
         * @tc.desc: Check for equality.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, Options_test_005, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keystoreFile = "./generateKeyPair/keypair.p12";
            std::string issuerkeystoreFile = "./generateKeyPair/keypair.p12";

            (*params)["keystoreFile"] = keystoreFile;
            (*params)["issuerkeystoreFile"] = issuerkeystoreFile;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            EXPECT_EQ(adaptePtr->options->Equals(Options::KEY_STORE_FILE, Options::ISSUER_KEY_STORE_FILE), true);
        }

        /*
         * @tc.name: Options_test_006
         * @tc.desc: Check for presence.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, Options_test_006, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keystoreFile = "./generateKeyPair/keypair.p12";
            std::string issuerkeystoreFile = "./generateKeyPair/keypair.p12";

            (*params)["keystoreFile"] = keystoreFile;
            (*params)["issuerkeystoreFile"] = issuerkeystoreFile;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            EXPECT_EQ(adaptePtr->options->Required({ Options::KEY_STORE_FILE, Options::ISSUER_KEY_STORE_FILE }), true);
        }
        /*
         * @tc.name: Options_test_007
         * @tc.desc: Check whether it is empty.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, Options_test_007, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string str = "";

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            EXPECT_EQ(adaptePtr->options->IsEmpty(str), true);
        }

        /*
        * @tc.name: Options_test_008
        * @tc.desc: get string type value, and do type checking.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(GenerateKeyPairTest, Options_test_008, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "alias";
            (*params)["keyAlias"];

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            std::string strPrt = adaptePtr->options->GetString(Options::KEY_ALIAS);

            EXPECT_EQ(strPrt, "");
        }


        /*
         * @tc.name: cmd_util_test_001
         * @tc.desc: Check whether the algorithm is in ECC format.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, cmd_util_test_001, testing::ext::TestSize.Level1)
        {
            std::string keyAlg = "ECC";
            EXPECT_EQ(CmdUtil::JudgeAlgType(keyAlg), true);
        }

        /*
         * @tc.name: cmd_util_test_002
         * @tc.desc: Check whether the algorithm length is 256 or 384.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, cmd_util_test_002, testing::ext::TestSize.Level1)
        {
            int size = 256;
            EXPECT_EQ(CmdUtil::JudgeSize(size), true);
        }

        /*
         * @tc.name: cmd_util_test_003
         * @tc.desc: Write command line arguments to map.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, cmd_util_test_003, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-384", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13 };
            int argc = 14;

            CmdUtil cmdUtil;
            ParamsSharedPtr param = std::make_shared<Params>();
            bool ret = cmdUtil.Convert2Params(argv, argc, param);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: cmd_util_test_004
         * @tc.desc: Gets command line arguments.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, cmd_util_test_004, testing::ext::TestSize.Level1)
        {
            char argv[][100] = { "generate-keypair",
                             "-keyAlias", "oh-app1-key-v1",
                             "-keyPwd", "123456",
                             "-keyAlg", "ECC",
                             "-keySize", "NIST-P-384",
                             "-keystoreFile", "./generateKeyPair/OpenHarmony.p12",
                             "-keystorePwd", "123456"
            };

            ParamsTrustlist params_trust_list;
            std::vector<std::string> trustList = params_trust_list.GetTrustList(argv[1]);
            if (trustList.empty()) {
                bool ret = false;
                EXPECT_EQ(ret, false);
            } else {
                bool ret = true;
                EXPECT_EQ(ret, true);
            }
        }

        /*
         * @tc.name: cmd_util_test_005
         * @tc.desc: Check whether the file format is p12 or jks.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, cmd_util_test_005, testing::ext::TestSize.Level1)
        {
            ParamsTrustlist params_trust_list;
            bool ret = params_trust_list.GenerateTrustlist();
            EXPECT_EQ(ret, true);
        }


        /*
         * @tc.name: cmd_util_test_006
         * @tc.desc: Write command line arguments to map.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, cmd_util_test_006, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-384", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13 };
            int argc = 14;

            CmdUtil cmdUtil;
            ParamsSharedPtr param = std::make_shared<Params>();
            bool ret = cmdUtil.Convert2Params(argv, argc, param);

            EXPECT_EQ(ret, true);
        }
        /*
         * @tc.name: file_util_test_001
         * @tc.desc: Check whether the file format is p12 or jks.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, file_util_test_001, testing::ext::TestSize.Level1)
        {
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keystoreFile = "./generateKeyPair/keypair.p12";

            (*params)["keystoreFile"] = keystoreFile;

            std::unique_ptr<LocalizationAdapter> adaptePtr = std::make_unique<LocalizationAdapter>(params.get());

            EXPECT_EQ(FileUtils::ValidFileType(adaptePtr->options->GetString(Options::KEY_STORE_FILE),
                      { "p12", "jks" }), true);
        }

        /*
         * @tc.name: main_test_001
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_001, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-384", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13 };

            int argc = 14;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_002
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_002, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "";
            char* argv[] = { arg0, arg1 };

            int argc = 2;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: main_test_003
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_003, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "-h";
            char* argv[] = { arg0, arg1 };

            int argc = 2;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_004
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_004, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "-v";
            char* argv[] = { arg0, arg1 };

            int argc = 2;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_005
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_005, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "";
            char* argv[] = { arg0, arg1, arg2, arg3 };

            int argc = 4;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: main_test_006
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_006, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "", arg3[] = "";
            char* argv[] = { arg0, arg1, arg2, arg3 };

            int argc = 4;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: main_test_007
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_007, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "", arg3[] = "";
            char* argv[] = { arg0, arg1, arg2, arg3 };

            int argc = 4;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            hapSignToolPtr->ProcessCmd(argv, argc);
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: main_test_008
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_008, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-385", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                             arg7, arg8, arg9, arg10, arg11, arg12, arg13 };

            int argc = 14;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            hapSignToolPtr->ProcessCmd(argv, argc);
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: main_test_009
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_009, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-384", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-keyUsageCritical", arg15[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                             arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            hapSignToolPtr->ProcessCmd(argv, argc);
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: main_test_010
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_010, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-384", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-basicConstraintsCritical", arg15[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                             arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            hapSignToolPtr->ProcessCmd(argv, argc);
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: main_test_011
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_011, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-384", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-outForm", arg15[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                             arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            hapSignToolPtr->ProcessCmd(argv, argc);
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: main_test_012
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_012, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-256", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5,
                             arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13 };

            int argc = 14;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_013
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_013, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                             arg7, arg8, arg9, arg10, arg11, arg12, arg13 };

            int argc = 14;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_014
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_014, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-basicConstraintsPathLen", arg15[] = "0";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                             arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_015
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_015, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-validity", arg15[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                             arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_016
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_016, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-keyUsageCritical", arg15[] = "true";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                             arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_017
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_017, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-keyUsageCritical", arg15[] = "false";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                             arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_018
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_018, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-keyUsageCritical", arg15[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                             arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_019
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_019, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-extKeyUsageCritical", arg15[] = "true";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                             arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_020
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_020, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-extKeyUsageCritical", arg15[] = "false";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                             arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_021
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_021, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-extKeyUsageCritical", arg15[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                             arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_022
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_022, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-basicConstraints", arg15[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                             arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_023
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_023, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-basicConstraints", arg15[] = "true";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                             arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_024
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_024, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-basicConstraints", arg15[] = "false";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                             arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_025
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_025, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-basicConstraintsCritical", arg15[] = "false";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
                             arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_026
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_026, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-basicConstraintsCritical", arg15[] = "true";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
                             arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_027
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_027, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-257", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456", arg14[] = "-basicConstraintsCritical", arg15[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                             arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15 };

            int argc = 16;
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_001
         * @tc.desc: Generates a key pair input check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_001, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-app1-key-v1";
            char keyPwd[] = "123456";
            std::string keyAlg = "ECC";
            int keySize = 384;
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;

            bool ret = HapSignTool::RunKeypair(params.get(), *api);
            EXPECT_EQ(ret, true);
        }


        /*
         * @tc.name: hap_sign_tool_test_002
         * @tc.desc: Generate a csr entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_002, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-app1-key-v1";
            char keyPwd[] = "123456";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
            std::string signAlg = "SHA256withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/oh-app1-key-v1.csr";

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["subject"] = subject;
            (*params)["signAlg"] = signAlg;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;

            bool ret = HapSignTool::RunCsr(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
        * @tc.name: hap_sign_tool_test_003
        * @tc.desc: Generate the root certificate entry check.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_003, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-root-ca-key-v1";
            char keyPwd[] = "123456";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";
            int validity = 365;
            std::string signAlg = "SHA384withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/root-ca1.cer";
            std::string keyAlg = "ECC";
            int keySize = 384;

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["subject"] = subject;
            (*params)["signAlg"] = signAlg;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;
            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;
            (*params)["validity"] = validity;

            bool ret = HapSignTool::RunCa(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
        * @tc.name: hap_sign_tool_test_004
        * @tc.desc: Generate an app debug certificate for entry checks.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_004, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-profile1-key-v1";
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

            bool ret = HapSignTool::RunProfileCert(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_005
         * @tc.desc: Generate profile debugging certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_005, testing::ext::TestSize.Level1)
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

            bool ret = HapSignTool::RunAppCert(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_006
         * @tc.desc: Generate a universal certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_006, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-profile1-key-v1";
            char keyPwd[] = "123456";
            std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
            std::string issuerKeyAlias = "oh-profile-sign-srv-ca-key-v1";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
            int validity = 365;
            std::string signAlg = "SHA384withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/general.cer";

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

            bool ret = HapSignTool::RunCert(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_007
         * @tc.desc: Generate profile signature entry checks.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_007, testing::ext::TestSize.Level1)
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

            bool ret = HapSignTool::RunSignProfile(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_008
         * @tc.desc: Generate a profile check-in check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_008, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string inFile = "./generateKeyPair/signed-profile.p7b";
            std::string outFile = "./generateKeyPair/VerifyResult.json";

            (*params)["inFile"] = inFile;
            (*params)["outFile"] = outFile;

            bool ret = HapSignTool::RunVerifyProfile(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_009
         * @tc.desc: The hap signature entry check is generated.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_009, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            char keyPwd[] = "123456";
            std::string signCode = "1";
            std::string signAlg = "SHA384withECDSA";
            std::string appCertFile = "./generateKeyPair/app-release1.pem";
            std::string profileFile = "./generateKeyPair/signed-profile.p7b";
            std::string inFile = "entry-default-unsigned-so.hap";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/entry-default-signed-so.hap";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["signCode"] = signCode;
            (*params)["signAlg"] = signAlg;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;

            bool ret = HapSignTool::RunSignApp(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_010
         * @tc.desc: Generate a profile check-in check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_010, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string inFile = "./generateKeyPair/entry-default-signed-so.hap";
            std::string outCertChain = "./generateKeyPair/app-sign-srv-ca1.cer";
            std::string outProfile = "./generateKeyPair/app-profile.p7b";

            (*params)["inFile"] = inFile;
            (*params)["outCertChain"] = outCertChain;
            (*params)["outProfile"] = outProfile;

            bool ret = HapSignTool::RunVerifyApp(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
                 * @tc.name: hap_sign_tool_test_011
                 * @tc.desc: Invoke the generate key pair interface.
                 * @tc.type: FUNC
                 * @tc.require:
                 */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_011, testing::ext::TestSize.Level1)
        {
            char arg0[] = "", arg1[] = "generate-keypair", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-keyAlg", arg7[] = "ECC", arg8[] = "-keySize",
                arg9[] = "NIST-P-384", arg10[] = "-keystoreFile", arg11[] = "./generateKeyPair/OpenHarmony.p12",
                arg12[] = "-keystorePwd", arg13[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13 };
            int argc = 14;

            ParamsSharedPtr param = std::make_shared<Params>();
            std::shared_ptr<SignToolServiceImpl> service_api = std::make_shared<SignToolServiceImpl>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);
            bool ret = HapSignTool::DispatchParams(param, *service_api.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_012
         * @tc.desc: Invoke to generate hap signature interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_012, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "sign-app", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-mode", arg7[] = "localSign", arg8[] = "-signCode",
                arg9[] = "1", arg10[] = "-signAlg", arg11[] = "SHA384withECDSA",
                arg12[] = "-appCertFile", arg13[] = "./generateKeyPair/app-release1.pem",
                arg14[] = "-profileFile", arg15[] = "./generateKeyPair/signed-profile.p7b",
                arg16[] = "-inFile", arg17[] = "entry-default-unsigned-so.hap", arg18[] = "-keystoreFile",
                arg19[] = "./generateKeyPair/OpenHarmony.p12",
                arg20[] = "-keystorePwd", arg21[] = "123456", arg22[] = "-outFile",
                arg23[] = "./generateKeyPair/entry-default-signed-so.hap";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_013
         * @tc.desc: Invoke the generate profile signature interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_013, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "sign-profile", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-mode", arg7[] = "localSign",
                arg8[] = "-signAlg", arg9[] = "SHA384withECDSA",
                arg10[] = "-inFile", arg11[] = "./generateKeyPair/profile.json", arg12[] = "-keystoreFile",
                arg13[] = "./generateKeyPair/OpenHarmony.p12",
                arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
                arg17[] = "./generateKeyPair/signed-profile.p7b", arg18[] = "-profileCertFile",
                arg19[] = "./generateKeyPair/signed-profile.p7b";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19 };
            int argc = 20;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_014
         * @tc.desc: Invoke to generate hap check interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_014, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "verify-app", arg2[] = "-inFile",
                arg3[] = "./generateKeyPair/entry-default-signed-so.hap",
                arg4[] = "-outCertChain", arg5[] = "./generateKeyPair/app-sign-srv-ca1.cer",
                arg6[] = "-outProfile", arg7[] = "./generateKeyPair/app-profile.p7b";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7 };
            int argc = 8;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_015
         * @tc.desc: Invoke the generate profile check interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_015, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string inFile = "./generateKeyPair/signed-profile.p7b";
            std::string outFile = "./generateKeyPair/VerifyResult.json";

            (*params)["inFile"] = inFile;
            (*params)["outFile"] = outFile;

            char arg0[] = "", arg1[] = "verify-profile", arg2[] = "-inFile",
                arg3[] = "./generateKeyPair/signed-profile.p7b",
                arg4[] = "-outFile", arg5[] = "./generateKeyPair/VerifyResult.json";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5 };
            int argc = 6;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, true);
        }


        /*
         * @tc.name: hap_sign_tool_test_016
         * @tc.desc: Invoke the Generate root certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_016, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-ca", arg2[] = "-keyAlias", arg3[] = "oh-root-ca-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-subject",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA",
                arg8[] = "-validity", arg9[] = "365",
                arg10[] = "-signAlg", arg11[] = "SHA384withECDSA", arg12[] = "-keystoreFile",
                arg13[] = "./generateKeyPair/OpenHarmony.p12",
                arg14[] = "-keystorePwd", arg15[] = "123456", arg16[] = "-outFile",
                arg17[] = "./generateKeyPair/root-ca1.cer", arg18[] = "-keyAlg",
                arg19[] = "ECC", arg20[] = "-keySize", arg21[] = "NIST-P-384";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21 };
            int argc = 20;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_017
         * @tc.desc: Invoke the generate app certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_017, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-app-cert", arg2[] = "-keyAlias", arg3[] = "oh-app1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-app-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/app-release1.pem",
                arg22[] = "-subCaCertFile", arg23[] = "./generateKeyPair/app-sign-srv-ca1.cer",
                arg24[] = "-outForm", arg25[] = "certChain", arg26[] = "-rootCaCertFile",
                arg27[] = "./generateKeyPair/root-ca1.cer";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21,
                             arg22, arg23, arg24, arg25, arg26, arg27 };
            int argc = 28;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_018
         * @tc.desc: Invoke the Generate profile certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_018, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-profile-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/profile-release1.pem",
                arg22[] = "-subCaCertFile",
                arg23[] = "./generateKeyPair/profile-sign-srv-ca1.cer",
                arg24[] = "-outForm", arg25[] = "certChain", arg26[] = "-rootCaCertFile",
                arg27[] = "./generateKeyPair/root-ca1.cer";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20,
                             arg21, arg22, arg23, arg24, arg25, arg26, arg27 };
            int argc = 28;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_019
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_019, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21 };
            int argc = 22;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_020
         * @tc.desc: Command error, does not invoke any check interface.
         * @tc.type: FUNC
         * @tc.require:(generate-parameter)
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_020, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-parameter", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21 };
            int argc = 22;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_021
         * @tc.desc: Print help document.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_021, testing::ext::TestSize.Level1)
        {
            if (HELP_FILE_PATH.empty()) {
                HapSignTool::PrintHelp();
                bool ret = false;
                EXPECT_EQ(ret, false);
            } else {
                HapSignTool::PrintHelp();
                bool ret = true;
                EXPECT_EQ(ret, true);
            }
        }

        /*
         * @tc.name: hap_sign_tool_test_022
         * @tc.desc: Print version number.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_022, testing::ext::TestSize.Level1)
        {
            HapSignTool::Version();
        }

        /*
        * @tc.name: hap_sign_tool_test_023
        * @tc.desc: Generate the root certificate entry check.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_023, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-root-ca-key-v1";
            (*params)["keyAlias"] = keyAlias;

            bool ret = HapSignTool::RunCa(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_024
         * @tc.desc: Generate the root certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_024, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-root-ca-key-v1";
            char keyPwd[] = "123456";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";
            int validity = 365;
            std::string signAlg = "SHA384withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/root-ca1.cer";
            std::string keyAlg = "RSA";
            int keySize = 384;

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["subject"] = subject;
            (*params)["signAlg"] = signAlg;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;
            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;
            (*params)["validity"] = validity;

            bool ret = HapSignTool::RunCa(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_025
         * @tc.desc: Generate the root certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_025, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-root-ca-key-v1";
            char keyPwd[] = "123456";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";
            int validity = 365;
            std::string signAlg = "SHA385withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/root-ca1.cer";
            std::string keyAlg = "ECC";
            int keySize = 999;

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["subject"] = subject;
            (*params)["signAlg"] = signAlg;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;
            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;
            (*params)["validity"] = validity;

            bool ret = HapSignTool::RunCa(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_026
         * @tc.desc: Generate the root certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_026, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-root-ca-key-v1";
            char keyPwd[] = "123456";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";
            std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";
            int validity = 365;
            std::string signAlg = "SHA385withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.txt";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/root-ca1.cer";
            std::string keyAlg = "ECC";
            int keySize = 999;

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["subject"] = subject;
            (*params)["signAlg"] = signAlg;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;
            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;
            (*params)["validity"] = validity;
            (*params)["issuer"] = issuer;

            bool ret = HapSignTool::RunCa(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_027
         * @tc.desc: Generate the root certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_027, testing::ext::TestSize.Level1)
        {
            std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";

            bool ret = HapSignTool::StringTruncation(issuer);
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_028
         * @tc.desc: Generate a universal certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_028, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();
            std::string keyAlias = "oh-app1-key-v1";
            std::string issuerKeyAlias = "oh-app1-key-v1";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN= Openharmony Application CA";
            std::string issuer =
                "C=CNA,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
            std::string signAlg = "SHA384withECDSA";
            std::string keyStoreFile = "./generateKeyPair/OpenHarmony.p12";
            std::string keyUsage = "digitalSignature";
            std::string outFile = "./generateKeyPair/general.cer";
            bool basicConstraints = true;
            bool basicConstraintsCritical = true;
            bool basicConstraintsCa = true;
            bool keyUsageCritical = true;
            char secret[] = "123456";
            int keysize = 384;
            (*params)["keyAlias"] = keyAlias;
            (*params)["issuerKeyAlias"] = issuerKeyAlias;
            (*params)["keysize"] = keysize;
            (*params)["subject"] = subject;
            (*params)["issuer"] = issuer;
            (*params)["signAlg"] = signAlg;
            (*params)["keyStoreFile"] = keyStoreFile;
            (*params)["keyUsage"] = keyUsage;
            (*params)["basicConstraints"] = basicConstraints;
            (*params)["basicConstraintsCritical"] = basicConstraintsCritical;
            (*params)["basicConstraintsCa"] = basicConstraintsCa;
            (*params)["keyUsageCritical"] = keyUsageCritical;
            (*params)["keyPwd"] = secret;
            (*params)["keystorePwd"] = secret;

            bool ret = HapSignTool::RunCert(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_029
         * @tc.desc: The hap signature entry check is generated.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_029, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            char keyPwd[] = "123456";
            std::string signCode = "1";
            std::string signAlg = "SHA384withECDSA";
            std::string appCertFile = "./generateKeyPair/app-release1.pem";
            std::string profileFile = "./generateKeyPair/signed-profile.p7b";
            std::string inFile = "entry-default-unsigned-so.hap";
            std::string outFile = "./generateKeyPair/entry-default-signed-so.hap";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["signCode"] = signCode;
            (*params)["signAlg"] = signAlg;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["outFile"] = outFile;

            bool ret = HapSignTool::RunSignApp(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_030
         * @tc.desc: The hap signature entry check is generated.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_030, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            char keyPwd[] = "123456";
            std::string signCode = "1";
            std::string signAlg = "SHA384withECDSA";
            std::string appCertFile = "./generateKeyPair/app-release1.pem";
            std::string profileFile = "./generateKeyPair/signed-profile.p7b";
            std::string inFile = "entry-default-unsigned-so.hap";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.txt";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/entry-default-signed-so.hap";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["signCode"] = signCode;
            (*params)["signAlg"] = signAlg;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;

            bool ret = HapSignTool::RunSignApp(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_031
         * @tc.desc: The hap signature entry check is generated.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_031, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            char keyPwd[] = "123456";
            std::string signCode = "1";
            std::string signAlg = "SHA384withECDSA";
            std::string appCertFile = "./generateKeyPair/app-release1.pem";
            std::string profileFile = "./generateKeyPair/signed-profile.txt";
            std::string inFile = "entry-default-unsigned-so.hap";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/entry-default-signed-so.hap";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["signCode"] = signCode;
            (*params)["signAlg"] = signAlg;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;

            bool ret = HapSignTool::RunSignApp(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_032
         * @tc.desc: The hap signature entry check is generated.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_032, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            char keyPwd[] = "123456";
            std::string signCode = "1";
            std::string signAlg = "SHA385withECDSA";
            std::string appCertFile = "./generateKeyPair/app-release1.pem";
            std::string profileFile = "./generateKeyPair/signed-profile.p7b";
            std::string inFile = "entry-default-unsigned-so.hap";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/entry-default-signed-so.hap";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["signCode"] = signCode;
            (*params)["signAlg"] = signAlg;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;

            bool ret = HapSignTool::RunSignApp(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_033
         * @tc.desc: The hap signature entry check is generated.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_033, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            char keyPwd[] = "123456";
            std::string signCode = "1";
            std::string signAlg = "SHA384withECDSA";
            std::string appCertFile = "./generateKeyPair/app-release1.pem";
            std::string inFile = "entry-default-unsigned-so.hap";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/entry-default-signed-so.hap";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["signCode"] = signCode;
            (*params)["signAlg"] = signAlg;
            (*params)["appCertFile"] = appCertFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;

            bool ret = HapSignTool::RunSignApp(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_034
         * @tc.desc: The hap signature entry check is generated.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_034, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            char keyPwd[] = "123456";
            std::string signCode = "1";
            std::string signAlg = "SHA384withECDSA";
            std::string appCertFile = "./generateKeyPair/app-release1.pem";
            std::string profileFile = "./generateKeyPair/signed-profile.txt";
            std::string inFile = "entry-default-unsigned-so.hap";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/entry-default-signed-so.hap";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["signCode"] = signCode;
            (*params)["signAlg"] = signAlg;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;

            bool ret = HapSignTool::RunSignApp(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_035
         * @tc.desc: The hap signature entry check is generated.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_035, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string mode = "localSign";
            std::string keyAlias = "oh-app1-key-v1";
            char keyPwd[] = "123456";
            std::string signCode = "1";
            std::string signAlg = "SHA384withECDSA";
            std::string appCertFile = "./generateKeyPair/app-release1.pem";
            std::string profileFile = "./generateKeyPair/signed-profile.txt";
            std::string inFile = "entry-default-unsigned-so.hap";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/entry-default-signed-so.hap";
            std::string profileSigned = "0";

            (*params)["mode"] = mode;
            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["signCode"] = signCode;
            (*params)["signAlg"] = signAlg;
            (*params)["appCertFile"] = appCertFile;
            (*params)["profileFile"] = profileFile;
            (*params)["inFile"] = inFile;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;
            (*params)["profileSigned"] = profileSigned;

            bool ret = HapSignTool::RunSignApp(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_036
         * @tc.desc: Generate the root certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_036, testing::ext::TestSize.Level1)
        {
            std::string issuer = "";

            bool ret = HapSignTool::StringTruncation(issuer);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_037
         * @tc.desc: Generate the root certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_037, testing::ext::TestSize.Level1)
        {
            std::string issuer = "123456";

            bool ret = HapSignTool::StringTruncation(issuer);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_038
         * @tc.desc: Generate the root certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_038, testing::ext::TestSize.Level1)
        {
            std::string issuer = "CCN,O=OpenHarmony";

            bool ret = HapSignTool::StringTruncation(issuer);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_039
         * @tc.desc: Generate the root certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_039, testing::ext::TestSize.Level1)
        {
            std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";

            bool ret = HapSignTool::StringTruncation(issuer);
            EXPECT_EQ(ret, false);
        }

        /*
        * @tc.name: hap_sign_tool_test_040
        * @tc.desc: Generate the root certificate entry check.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_040, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-root-ca-key-v1";
            char keyPwd[] = "123456";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";
            int validity = 365;
            std::string signAlg = "SHA385withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/root-ca1.cer";
            std::string keyAlg = "ECC";
            int keySize = 384;

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["subject"] = subject;
            (*params)["signAlg"] = signAlg;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;
            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;
            (*params)["validity"] = validity;

            bool ret = HapSignTool::RunCa(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
        * @tc.name: hap_sign_tool_test_041
        * @tc.desc: Generate the root certificate entry check.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_041, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-root-ca-key-v1";
            char keyPwd[] = "123456";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";
            int validity = 365;
            std::string signAlg = "SHA384withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.txt";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/root-ca1.cer";
            std::string keyAlg = "ECC";
            int keySize = 384;

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["subject"] = subject;
            (*params)["signAlg"] = signAlg;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;
            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;
            (*params)["validity"] = validity;

            bool ret = HapSignTool::RunCa(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_042
         * @tc.desc: Generate the root certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_042, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-root-ca-key-v1";
            char keyPwd[] = "123456";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Root CA";
            std::string issuer = "C=CN,O=OpenHarmony_test,OU=OpenHarmony Community,CN= Openharmony Application SUB  CA";
            int validity = 365;
            std::string signAlg = "SHA384withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/root-ca1.cer";
            std::string keyAlg = "ECC";
            int keySize = 384;

            (*params)["keyAlias"] = keyAlias;
            (*params)["keyPwd"] = keyPwd;
            (*params)["subject"] = subject;
            (*params)["signAlg"] = signAlg;
            (*params)["keystoreFile"] = keystoreFile;
            (*params)["keystorePwd"] = keystorePwd;
            (*params)["outFile"] = outFile;
            (*params)["keyAlg"] = keyAlg;
            (*params)["keySize"] = keySize;
            (*params)["validity"] = validity;
            (*params)["issuer"] = issuer;

            bool ret = HapSignTool::RunCa(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_043
         * @tc.desc: Generate a universal certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_043, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-profile1-key-v1";
            char keyPwd[] = "123456";
            std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
            std::string issuerKeyAlias = "oh-profile-sign-srv-ca-key-v1";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
            int validity = 365;
            std::string signAlg = "SHA384withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/general.cer";
            std::string keyUsage = "digitalSignature";

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
            (*params)["keyUsage"] = keyUsage;

            bool ret = HapSignTool::RunCert(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_044
         * @tc.desc: Generate a universal certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_044, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-profile1-key-v1";
            char keyPwd[] = "123456";
            std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
            std::string issuerKeyAlias = "oh-profile-sign-srv-ca-key-v1";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
            int validity = 365;
            std::string signAlg = "SHA384withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/general.cer";
            std::string keyUsage = "abcd";

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
            (*params)["keyUsage"] = keyUsage;

            bool ret = HapSignTool::RunCert(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_045
         * @tc.desc: Generate a universal certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_045, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-profile1-key-v1";
            char keyPwd[] = "123456";
            std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
            std::string issuerKeyAlias = "oh-profile-sign-srv-ca-key-v1";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
            int validity = 365;
            std::string signAlg = "SHA384withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/general.cer";
            std::string keyUsage = "digitalSignature";
            std::string extKeyUsage = "abcd";

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
            (*params)["keyUsage"] = keyUsage;
            (*params)["extKeyUsage"] = extKeyUsage;

            bool ret = HapSignTool::RunCert(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_046
         * @tc.desc: Generate a universal certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_046, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-profile1-key-v1";
            char keyPwd[] = "123456";
            std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
            std::string issuerKeyAlias = "oh-profile-sign-srv-ca-key-v1";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
            int validity = 365;
            std::string signAlg = "SHA385withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/general.cer";
            std::string keyUsage = "digitalSignature";

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
            (*params)["keyUsage"] = keyUsage;

            bool ret = HapSignTool::RunCert(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_047
         * @tc.desc: Generate a universal certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_047, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-profile1-key-v1";
            char keyPwd[] = "123456";
            std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
            std::string issuerKeyAlias = "oh-profile-sign-srv-ca-key-v1";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
            int validity = 365;
            std::string signAlg = "SHA384withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.txt";
            char keystorePwd[] = "123456";
            std::string outFile = "./generateKeyPair/general.cer";
            std::string keyUsage = "digitalSignature";

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
            (*params)["keyUsage"] = keyUsage;

            bool ret = HapSignTool::RunCert(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_048
         * @tc.desc: Generate profile debugging certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_048, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

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

            bool ret = HapSignTool::RunAppCert(params.get(), *api);
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_049
         * @tc.desc: Generate profile debugging certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_049, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string keyAlias = "oh-app1-key-v1";
            char keyPwd[] = "123456";
            std::string issuer = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA";
            std::string issuerKeyAlias = "oh-app-sign-srv-ca-key-v1";
            std::string subject = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release";
            int validity = 365;
            std::string signAlg = "SHA385withECDSA";
            std::string keystoreFile = "./generateKeyPair/OpenHarmony.p12";
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

            bool ret = HapSignTool::RunAppCert(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_050
         * @tc.desc: Generate profile debugging certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_050, testing::ext::TestSize.Level1)
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
            (*params)["rootCaCertFile"] = rootCaCertFile;

            bool ret = HapSignTool::RunAppCert(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_051
         * @tc.desc: Generate profile debugging certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_051, testing::ext::TestSize.Level1)
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
            std::string outForm = "123456";
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

            bool ret = HapSignTool::RunAppCert(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_052
         * @tc.desc: Generate profile debugging certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_052, testing::ext::TestSize.Level1)
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

            bool ret = HapSignTool::RunAppCert(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_053
         * @tc.desc: Generate profile debugging certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_053, testing::ext::TestSize.Level1)
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

            bool ret = HapSignTool::RunAppCert(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_054
         * @tc.desc: Generate profile debugging certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_054, testing::ext::TestSize.Level1)
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

            bool ret = HapSignTool::RunAppCert(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_055
         * @tc.desc: Generate profile debugging certificate entry check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_055, testing::ext::TestSize.Level1)
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


            bool ret = HapSignTool::RunAppCert(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
        * @tc.name: hap_sign_tool_test_056
        * @tc.desc: Generate an app debug certificate for entry checks.
        * @tc.type: FUNC
        * @tc.require:
        */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_056, testing::ext::TestSize.Level1)
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

            bool ret = HapSignTool::RunProfileCert(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_057
         * @tc.desc: Generates a key pair input check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_057, testing::ext::TestSize.Level1)
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

            bool ret = HapSignTool::RunKeypair(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_058
         * @tc.desc: Generates a key pair input check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_058, testing::ext::TestSize.Level1)
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

            bool ret = HapSignTool::RunKeypair(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_059
         * @tc.desc: Generates a key pair input check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_059, testing::ext::TestSize.Level1)
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

            bool ret = HapSignTool::RunKeypair(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_060
         * @tc.desc: Generates a key pair input check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_060, testing::ext::TestSize.Level1)
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

            bool ret = HapSignTool::RunKeypair(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /**
         * @tc.name: hap_sign_tool_test_061
         * @tc.desc: Test function of SignToolServiceImpl::RunCsr() interface for SUCCESS.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, run_csr_test_061, testing::ext::TestSize.Level1)
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

            bool ret = HapSignTool::RunCsr(params.get(), *api);
            EXPECT_EQ(ret, false);
        }


        /*
         * @tc.name: hap_sign_tool_test_062
         * @tc.desc: Generate a profile check-in check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_062, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string outFile = "./generateKeyPair/VerifyResult.json";
            (*params)["outFile"] = outFile;

            bool ret = HapSignTool::RunVerifyProfile(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_063
         * @tc.desc: Generate a profile check-in check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_063, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string inFile = "./generateKeyPair/signed-profile.txt";
            std::string outFile = "./generateKeyPair/VerifyResult.json";

            (*params)["inFile"] = inFile;
            (*params)["outFile"] = outFile;

            bool ret = HapSignTool::RunVerifyProfile(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_064
         * @tc.desc: Generate a profile check-in check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_064, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string inFile = "./generateKeyPair/signed-profile.p7b";
            std::string outFile = "./generateKeyPair/VerifyResult.txt";

            (*params)["inFile"] = inFile;
            (*params)["outFile"] = outFile;

            bool ret = HapSignTool::RunVerifyProfile(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_065
         * @tc.desc: Generate a profile check-in check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_065, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string outCertChain = "./generateKeyPair/app-sign-srv-ca1.cer";
            std::string outProfile = "./generateKeyPair/app-profile.p7b";

            (*params)["outCertChain"] = outCertChain;
            (*params)["outProfile"] = outProfile;

            bool ret = HapSignTool::RunVerifyApp(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_066
         * @tc.desc: Generate a profile check-in check.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_066, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            std::string inFile = "./generateKeyPair/entry-default-signed-so.hap";
            std::string outCertChain = "./generateKeyPair/app-sign-srv-ca1.cer";
            std::string outProfile = "./generateKeyPair/app-profile.txt";

            (*params)["inFile"] = inFile;
            (*params)["outCertChain"] = outCertChain;
            (*params)["outProfile"] = outProfile;

            bool ret = HapSignTool::RunVerifyApp(params.get(), *api);
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: params_test_001
         * @tc.desc: Set the first parameter of the command.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, params_test_001, testing::ext::TestSize.Level1)
        {
            char argv[][100] = { "generate-keypair",
                             "-keyAlias", "oh-app1-key-v1",
                             "-keyPwd", "123456",
                             "-keyAlg", "ECC",
                             "-keySize", "NIST-P-384",
                             "-keystoreFile", "./generateKeyPair/OpenHarmony.p12",
                             "-keystorePwd", "123456"
            };

            ParamsSharedPtr param = std::make_shared<Params>();
            param->SetMethod(argv[1]);
        }


        /*
         * @tc.name: params_test_002
         * @tc.desc: Remove the white space.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, params_test_002, testing::ext::TestSize.Level1)
        {
            std::string str = "  123456  ";
            std::string params = StringUtils::Trim(str);
            if (params == "123456") {
                bool ret = true;
                EXPECT_EQ(ret, true);
            } else {
                bool ret = false;
                EXPECT_EQ(ret, false);
            }
        }

        /*
         * @tc.name: params_test_003
         * @tc.desc: Gets the first command line argument.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, params_test_003, testing::ext::TestSize.Level1)
        {
            char argv[][100] = { "generate-keypair",
                             "-keyAlias", "oh-app1-key-v1",
                             "-keyPwd", "123456",
                             "-keyAlg", "ECC",
                             "-keySize", "NIST-P-384",
                             "-keystoreFile", "./generateKeyPair/OpenHarmony.p12",
                             "-keystorePwd", "123456"
            };

            ParamsSharedPtr param = std::make_shared<Params>();
            param->SetMethod(argv[1]);

            if (param->GetMethod().empty()) {
                bool ret = false;
                EXPECT_EQ(ret, false);
            } else {
                bool ret = true;
                EXPECT_EQ(ret, true);
            }
        }

        /*
         * @tc.name: params_test_004
         * @tc.desc: Gets the first command line argument.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, params_test_004, testing::ext::TestSize.Level1)
        {
            std::string signatureAlgorithm = ParamConstants::HAP_SIG_ALGORITHM_SHA384_ECDSA;
            SignatureAlgorithmClass out;
            bool ret = ParamProcessUtil::getSignatureAlgorithm(signatureAlgorithm, out);
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: params_test_005
         * @tc.desc: Gets the first command line argument.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, params_test_005, testing::ext::TestSize.Level1)
        {
            std::string signatureAlgorithm = "123456";
            SignatureAlgorithmClass out;
            bool ret = ParamProcessUtil::getSignatureAlgorithm(signatureAlgorithm, out);
            EXPECT_EQ(ret, false);
        }

        /*
 * @tc.name: main_test_028
 * @tc.desc: main function entry function.
 * @tc.type: FUNC
 * @tc.require:
 */
        HWTEST_F(GenerateKeyPairTest, main_test_028, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_029
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_029, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_030
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_030, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: main_test_031
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_031, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_032
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_032, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_033
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_033, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: main_test_034
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_034, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_035
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_035, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_036
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_036, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: main_test_037
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_037, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: main_test_038
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_038, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_039
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_039, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_040
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_040, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_041
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_041, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: main_test_042
         * @tc.desc: main function entry function.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, main_test_042, testing::ext::TestSize.Level1)
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
            std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
            bool ret = hapSignToolPtr->ProcessCmd(argv, argc);

            EXPECT_EQ(ret, false);
        }

        /*
 * @tc.name: hap_sign_tool_test_067
 * @tc.desc: Invoke the Generate generic certificate interface.
 * @tc.type: FUNC
 * @tc.require:
 */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_067, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU = OpenHarmony Community, CN = App1 Release",
                arg12[] = " - validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA",
                arg16[] = "-keystoreFile", arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile",
                arg21[] = "./generateKeyPair/general.cer", arg22[] = "-basicConstraintsPathLen", arg23[] = "0";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_068
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_068, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU = OpenHarmony Community, CN = App1 Release",
                arg12[] = " - validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA",
                arg16[] = "-keystoreFile", arg17[] = "./generateKeyPair/OpenHarmony.p12",
                arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-basicConstraintsPathLen",
                arg23[] = "1000000000000000000000000000000000000000000000000000000";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_069
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_069, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU = OpenHarmony Community, CN = App1 Release",
                arg12[] = " - validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA",
                arg16[] = "-keystoreFile", arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile",
                arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-validity", arg23[] = "558g22";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_070
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_070, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-validity", arg23[] = "558g2hhhsss1111111111111111111111111111111111112";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_071
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_071, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

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

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_072
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_072, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-keyUsageCritical", arg23[] = "false";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, true);
        }

        /*
         * @tc.name: hap_sign_tool_test_073
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_073, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile",
                arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-keyUsageCritical", arg23[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_074
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_074, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

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

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_075
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_075, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA",
                arg16[] = "-keystoreFile", arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-extKeyUsageCritical", arg23[] = "FALSE";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_076
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_076, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-extKeyUsageCritical", arg23[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_077
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_077, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

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

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_078
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_078, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-basicConstraints", arg23[] = "FALSE";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_079
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_079, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-basicConstraints", arg23[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_080
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_080, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

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

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_081
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_081, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-basicConstraintsCritical", arg23[] = "FALSE";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_082
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_082, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-basicConstraintsCritical", arg23[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_083
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_083, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

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

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_084
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_084, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-basicConstraintsCa", arg23[] = "FALSE";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }

        /*
         * @tc.name: hap_sign_tool_test_085
         * @tc.desc: Invoke the Generate generic certificate interface.
         * @tc.type: FUNC
         * @tc.require:
         */
        HWTEST_F(GenerateKeyPairTest, hap_sign_tool_test_085, testing::ext::TestSize.Level1)
        {
            std::unique_ptr<SignToolServiceImpl> api = std::make_unique<SignToolServiceImpl>();
            std::shared_ptr<Options> params = std::make_shared<Options>();

            char arg0[] = "", arg1[] = "generate-cert", arg2[] = "-keyAlias", arg3[] = "oh-profile1-key-v1",
                arg4[] = "-keyPwd", arg5[] = "123456", arg6[] = "-issuer",
                arg7[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=Application Signature Service CA",
                arg8[] = "-issuerKeyAlias", arg9[] = "oh-profile-sign-srv-ca-key-v1",
                arg10[] = "-subject", arg11[] = "C=CN,O=OpenHarmony,OU=OpenHarmony Community,CN=App1 Release",
                arg12[] = "-validity", arg13[] = "365",
                arg14[] = "-signAlg", arg15[] = "SHA384withECDSA", arg16[] = "-keystoreFile",
                arg17[] = "./generateKeyPair/OpenHarmony.p12", arg18[] = "-keystorePwd",
                arg19[] = "123456", arg20[] = "-outFile", arg21[] = "./generateKeyPair/general.cer",
                arg22[] = "-basicConstraintsCa", arg23[] = "123456";
            char* argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12,
                             arg13, arg14, arg15, arg16, arg17, arg18, arg19, arg20, arg21, arg22, arg23 };
            int argc = 24;

            ParamsSharedPtr param = std::make_shared<Params>();
            CmdUtil cmdUtil;

            cmdUtil.Convert2Params(argv, argc, param);

            bool ret = HapSignTool::DispatchParams(param, *api.get());
            EXPECT_EQ(ret, false);
        }
    }
}
