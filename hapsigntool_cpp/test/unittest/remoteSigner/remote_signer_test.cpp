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
#include <gtest/gtest.h>

#include "remote_sign_provider.h"
#include "packet_helper.h"

char* GetRemoteSignerWholePacket();
namespace OHOS {
namespace SignatureTools {
const char* g_remoteSignerWholeHapPath = "./remoteSigner/whole.hap";
class RemoteSignerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RemoteSignerTest::SetUpTestCase(void)
{
    (void)Base64DecodeStringToFile(GetRemoteSignerWholePacket(), g_remoteSignerWholeHapPath);
    sync();
}

void RemoteSignerTest::TearDownTestCase(void)
{
    (void)remove(g_remoteSignerWholeHapPath);
    sync();
}

void RemoteSignerTest::SetUp()
{
}

void RemoteSignerTest::TearDown()
{
}

/**
 * @tc.name: RemoteSignerTest
 * @tc.desc: Test RemoteSigner interface.
 * @tc.type: FUNC
 * @tc.require: SR000H63TL
 */
HWTEST_F(RemoteSignerTest, RemoteSignerTest001, testing::ext::TestSize.Level1)
{
    std::string mode = "remoteSign";
    std::string keyAlias = "oh-app1-key-v1";
    std::string profileFile = "./remoteSigner/signed-profile.p7b";
    std::string signAlg = "SHA256withECDSA";
    std::string signCode = "1";
    std::string compatibleVersion = "8";
    std::string inFile = g_remoteSignerWholeHapPath;
    std::string outFile = "./remoteSigner/signed.hap";
    std::string signServer = "./remoteSigner/app-release1.pem";
    std::string signerPluginV1 = "./remoteSigner/libremote_signer.z.so";
    std::string signerPluginV2 = "./remoteSigner/libremote_signer_without_create.z.so";
    std::string signerPluginV3 = "./remoteSigner/dummy.z.so";
    std::string onlineAuthMode = "./remoteSigner/OpenHarmony.p12";
    std::string username = "123456";
    char userPwd[] = "123456";

    std::shared_ptr<Options> params = std::make_shared<Options>();
    (*params)["mode"] = mode;
    (*params)["keyAlias"] = keyAlias;
    (*params)["profileFile"] = profileFile;
    (*params)["signAlg"] = signAlg;
    (*params)["signCode"] = signCode;
    (*params)["compatibleVersion"] = compatibleVersion;
    (*params)["inFile"] = inFile;
    (*params)["outFile"] = outFile;
    (*params)["signServer"] = signServer;
    (*params)["onlineAuthMode"] = onlineAuthMode;
    (*params)["username"] = username;
    (*params)["userPwd"] = userPwd;

    /*
     * @tc.steps: step1. test remoteSign full process
     * @tc.expected: step1. make the remote sign so file is right, the return will be true.
     */
    (*params)["signerPlugin"] = signerPluginV1;
    std::unique_ptr<SignProvider> signProvider1 = std::make_unique<RemoteSignProvider>();
    ASSERT_TRUE(signProvider1->Sign(params.get()));

    /*
     * @tc.steps: step1. test remoteSign full process
     * @tc.expected: step1. make the remote sign so file is right, the return will be true.
     */
    (*params)["signerPlugin"] = signerPluginV2;
    std::unique_ptr<SignProvider> signProvider2 = std::make_unique<RemoteSignProvider>();
    ASSERT_FALSE(signProvider2->Sign(params.get()));

    /*
     * @tc.steps: step1. test remoteSign full process
     * @tc.expected: step1. make the remote sign so file is right, the return will be true.
     */
    (*params)["signerPlugin"] = signerPluginV3;
    std::unique_ptr<SignProvider> signProvider3 = std::make_unique<RemoteSignProvider>();
    ASSERT_FALSE(signProvider3->Sign(params.get()));
}
} // namespace SignatureTools
} // namespace OHOS