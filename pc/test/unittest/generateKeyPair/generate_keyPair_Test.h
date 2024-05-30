#ifndef OHOS_GENERATE_KEYPAIR_TEST_H
#define OHOS_GENERATE_KEYPAIR_TEST_H

#include <gtest/gtest.h>
#include "signature_tools_log.h"
#include "options.h"
#include "sign_tool_service_impl.h"
#include "localization_adapter.h"
#include "openssl/ssl.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "cmd_util.h"
#include "file_utils.h"
#include "hap_sign_tool.h"
#include "constant.h"
#include "params.h"
#include "params_trust_list.h"
#include "param_process_util.h"
#include "param_constants.h"

namespace OHOS {
    namespace SignatureTools {
        class GenerateKeyPairTest : public testing::Test {
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
    }
}
#endif