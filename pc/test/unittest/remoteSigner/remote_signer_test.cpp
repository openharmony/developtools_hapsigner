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

#include "remote_sign_provider.h"

namespace OHOS {
namespace SignatureTools {
class RemoteSignerTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: Test RemoteSigner
 * @tc.desc: Test RemoteSigner interface for SUCCESS.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RemoteSignerTest, RemoteSignerTest001, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignProvider> signProvider = std::make_unique<RemoteSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "remoteSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string profileFile = "./remoteSigner/signed-profile.p7b";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "1";
    std::string compatibleVersion = "8";
    std::string inFile = "./remoteSigner/entry-default-unsigned-so.hap";
    std::string outFile = "./remoteSigner/entry-default-signed-so.hap";
    std::string signServer = "./remoteSigner/app-release1.pem";
    std::string signerPlugin = "./libremote_signer.z.so";
    std::string onlineAuthMode = "./remoteSigner/OpenHarmony.p12";
    std::string username = "123456";
    char userPwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["profileFile"] = profileFile;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["compatibleVersion"] = compatibleVersion;
    (*params)["inFile"] = inFile;
    (*params)["outFile"] = outFile;
    (*params)["signServer"] = signServer;
    (*params)["signerPlugin"] = signerPlugin;
    (*params)["onlineAuthMode"] = onlineAuthMode;
    (*params)["username"] = username;
    (*params)["userPwd"] = userPwd;

    bool res = signProvider->Sign(params.get());
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: Test RemoteSigner
 * @tc.desc: Test RemoteSigner interface for FAIL without so file.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RemoteSignerTest, RemoteSignerTest002, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignProvider> signProvider = std::make_unique<RemoteSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "remoteSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string profileFile = "./remoteSigner/signed-profile.p7b";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "1";
    std::string compatibleVersion = "8";
    std::string inFile = "./remoteSigner/entry-default-unsigned-so.hap";
    std::string outFile = "./remoteSigner/entry-default-signed-so.hap";
    std::string signServer = "./remoteSigner/app-release1.pem";
    std::string signerPlugin = "./dummy.z.so";
    std::string onlineAuthMode = "./remoteSigner/OpenHarmony.p12";
    std::string username = "123456";
    char userPwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["profileFile"] = profileFile;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["compatibleVersion"] = compatibleVersion;
    (*params)["inFile"] = inFile;
    (*params)["outFile"] = outFile;
    (*params)["signServer"] = signServer;
    (*params)["signerPlugin"] = signerPlugin;
    (*params)["onlineAuthMode"] = onlineAuthMode;
    (*params)["username"] = username;
    (*params)["userPwd"] = userPwd;

    bool res = signProvider->Sign(params.get());
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: Test RemoteSigner
 * @tc.desc: Test RemoteSigner interface for FAIL without Create function in so file.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RemoteSignerTest, RemoteSignerTest003, testing::ext::TestSize.Level1)
{
    std::unique_ptr<SignProvider> signProvider = std::make_unique<RemoteSignProvider>();
    std::shared_ptr<Options> params = std::make_shared<Options>();

    std::string mode = "remoteSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string profileFile = "./remoteSigner/signed-profile.p7b";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "1";
    std::string compatibleVersion = "8";
    std::string inFile = "./remoteSigner/entry-default-unsigned-so.hap";
    std::string outFile = "./remoteSigner/entry-default-signed-so.hap";
    std::string signServer = "./remoteSigner/app-release1.pem";
    std::string signerPlugin = "./libremote_signer_without_create.z.so";
    std::string onlineAuthMode = "./remoteSigner/OpenHarmony.p12";
    std::string username = "123456";
    char userPwd[] = "123456";

    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["profileFile"] = profileFile;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["compatibleVersion"] = compatibleVersion;
    (*params)["inFile"] = inFile;
    (*params)["outFile"] = outFile;
    (*params)["signServer"] = signServer;
    (*params)["signerPlugin"] = signerPlugin;
    (*params)["onlineAuthMode"] = onlineAuthMode;
    (*params)["username"] = username;
    (*params)["userPwd"] = userPwd;

    bool res = signProvider->Sign(params.get());
    EXPECT_EQ(res, false);
}

} // namespace SignatureTools
} // namespace OHOS