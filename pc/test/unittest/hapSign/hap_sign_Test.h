#ifndef OHOS_HAP_SIGN_TEST_H
#define OHOS_HAP_SIGN_TEST_H

#include <gtest/gtest.h>
#include "signature_tools_log.h"
#include "options.h"
#include "sign_tool_service_impl.h"
#include "localization_adapter.h"
#include "openssl/ssl.h"
#include "openssl/pem.h"
#include "openssl/err.h"

namespace OHOS {
    namespace SignatureTools {
        class HapSignTest : public testing::Test {
        public:
            static void SetUpTestCase(){};
            static void TearDownTestCase(){};
            void SetUp(){};
            void TearDown(){};
        };
    }
}

#endif