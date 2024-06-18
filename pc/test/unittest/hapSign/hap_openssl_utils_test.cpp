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
#include "hap_openssl_utils_test.h"
#include "params_run_tool.h"
#include "sign_hap.h"
#include "sign_provider.h"
#include "sign_tool_service_impl.h"
namespace OHOS {
namespace SignatureTools {
/*
 * @tc.name: hap_openssl_utils_test_001
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_001, testing::ext::TestSize.Level1)
{
    SIGNATURE_TOOLS_LOGI("hello world !!!");
    VerifyHapOpensslUtils VerifyHapOpenss;
    DigestParameter parameter;
    
    bool ret = VerifyHapOpenss.DigestInit(parameter);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_002, testing::ext::TestSize.Level1)
{
    SIGNATURE_TOOLS_LOGI("hello world !!!");
    VerifyHapOpensslUtils VerifyHapOpenss;
    DigestParameter parameter;
    parameter.md = EVP_sha256();
    bool ret = VerifyHapOpenss.DigestInit(parameter);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_003, testing::ext::TestSize.Level1)
{
    VerifyHapOpensslUtils VerifyHapOpenss;
    DigestParameter parameter;
    parameter.md = EVP_sha256();
    const unsigned char content[] = "123";
    int32_t len = 5;
    bool ret = VerifyHapOpenss.DigestUpdate(parameter, content, len);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_004, testing::ext::TestSize.Level1)
{
    VerifyHapOpensslUtils VerifyHapOpenss;
    DigestParameter parameter;
    parameter.md = EVP_sha256();
    int32_t len = 5;
    bool ret = VerifyHapOpenss.DigestUpdate(parameter, nullptr, len);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_005, testing::ext::TestSize.Level1)
{
    VerifyHapOpensslUtils VerifyHapOpenss;
    DigestParameter parameter;
    unsigned char dig[EVP_MAX_MD_SIZE];
    int32_t ret = VerifyHapOpenss.GetDigest(parameter, dig);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_006, testing::ext::TestSize.Level1)
{
    VerifyHapOpensslUtils VerifyHapOpenss;
    DigestParameter parameter;
    parameter.md = EVP_sha256();
    ByteBuffer chunk;
    std::vector<OptionalBlock> optionalBlocks;
    unsigned char out[EVP_MAX_MD_SIZE];
    int32_t ret = VerifyHapOpenss.GetDigest(chunk, optionalBlocks, parameter, out);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_007, testing::ext::TestSize.Level1)
{
    VerifyHapOpensslUtils VerifyHapOpenss;
    DigestParameter parameter;
    DigestParameter parameter_test(parameter);
    parameter_test = parameter;
    DigestParameter* parameter_ptr = &parameter;
    *parameter_ptr = parameter;
    ByteBuffer chunk;
    std::vector<OptionalBlock> optionalBlocks;
    unsigned char out[EVP_MAX_MD_SIZE];
    int32_t ret = VerifyHapOpenss.GetDigest(chunk, optionalBlocks, parameter, out);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_008, testing::ext::TestSize.Level1)
{
    VerifyHapOpensslUtils VerifyHapOpenss;
    int32_t digId = VerifyHapOpenss.GetDigestAlgorithmId(ALGORITHM_SHA384_WITH_ECDSA);
    EXPECT_EQ(digId, NID_sha384);
    digId = VerifyHapOpenss.GetDigestAlgorithmId(ALGORITHM_SHA512_WITH_ECDSA);
    EXPECT_EQ(digId, NID_sha512);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_009, testing::ext::TestSize.Level1)
{
    CertChain signCertChain;
    signCertChain.push_back(nullptr);
    std::vector<std::string> SignatureVec;
    bool ret = VerifyHapOpensslUtils::GetSignatures(signCertChain, SignatureVec);
    EXPECT_EQ(ret, false);
}



/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_010, testing::ext::TestSize.Level1)
{
    CertChain signCertChain;
    signCertChain.push_back(nullptr);
    std::vector<std::string> SignatureVec;
    bool ret = VerifyHapOpensslUtils::GetPublickeys(signCertChain, SignatureVec);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_011, testing::ext::TestSize.Level1)
{
    CertChain signCertChain;
    X509* t = X509_new();
    signCertChain.push_back(t);
    std::vector<std::string> SignatureVec;
    bool ret = VerifyHapOpensslUtils::GetPublickeys(signCertChain, SignatureVec);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_012, testing::ext::TestSize.Level1)
{
    Pkcs7Context pkcs7Context;
    bool ret = VerifyHapOpensslUtils::VerifyPkcs7(pkcs7Context);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_013, testing::ext::TestSize.Level1)
{
    Pkcs7Context pkcs7Context;
    pkcs7Context.p7 = PKCS7_new();
    PKCS7_set_type(pkcs7Context.p7, NID_pkcs7_signed);
    PKCS7_content_new(pkcs7Context.p7, NID_pkcs7_data);
    bool ret = VerifyHapOpensslUtils::VerifyPkcs7(pkcs7Context);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_015, testing::ext::TestSize.Level1)
{
    Pkcs7Context pkcs7Context;
    pkcs7Context.p7 = PKCS7_new();
    PKCS7_set_type(pkcs7Context.p7, NID_pkcs7_signed);
    PKCS7_content_new(pkcs7Context.p7, NID_pkcs7_data);
    bool ret = VerifyHapOpensslUtils::VerifyPkcs7(pkcs7Context);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_016, testing::ext::TestSize.Level1)
{
    Pkcs7Context pkcs7Context;
    pkcs7Context.p7 = PKCS7_new();
    PKCS7_set_type(pkcs7Context.p7, NID_pkcs7_data);
    bool ret = VerifyHapOpensslUtils::VerifyPkcs7(pkcs7Context);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_017, testing::ext::TestSize.Level1)
{
    Pkcs7Context pkcs7Context;
    pkcs7Context.p7 = PKCS7_new();
    PKCS7_set_type(pkcs7Context.p7, NID_pkcs7_signed);
    bool ret = VerifyHapOpensslUtils::VerifyPkcs7(pkcs7Context);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_018, testing::ext::TestSize.Level1)
{
    PKCS7* p7 = nullptr;
    Pkcs7Context pkcs7Context;
    bool ret = VerifyHapOpensslUtils::GetCertChains(p7, pkcs7Context);
    EXPECT_EQ(ret, false);
}

/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_019, testing::ext::TestSize.Level1)
{
    Pkcs7Context pkcs7Context;
    pkcs7Context.p7 = PKCS7_new();
    PKCS7_set_type(pkcs7Context.p7, NID_pkcs7_signed);
    PKCS7_content_new(pkcs7Context.p7, NID_pkcs7_data);
    PKCS7* p7_t = pkcs7Context.p7;
    bool ret = VerifyHapOpensslUtils::GetCertChains(p7_t, pkcs7Context);
    EXPECT_EQ(ret, false);
}
/*
 * @tc.name: hap_openssl_utils_test_002
 * @tc.desc: Verify Hap Openssl Utils.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HapOpensslUtilsTest, hap_openssl_utils_test_020, testing::ext::TestSize.Level1)
{
    CertChain signCertChain;
    signCertChain.push_back(nullptr);
    std::vector<std::string> SignatureVec;
    bool ret = VerifyHapOpensslUtils::GetSignatures(signCertChain, SignatureVec);
    EXPECT_EQ(ret, false);
}
} // namespace SignatureTools
} // namespace OHOS