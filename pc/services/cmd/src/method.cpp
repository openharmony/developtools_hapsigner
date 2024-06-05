/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
#include "method.h"
using namespace OHOS::SignatureTools;
const std::string Method::GENERATE_APP_CERT = "generate-app-cert";
const std::string Method::GENERATE_CA = "generate-ca";
const std::string Method::GENERATE_CERT = "generate-cert";
const std::string Method::GENERATE_CSR = "generate-csr";
const std::string Method::GENERATE_KEYPAIR = "generate-keypair";
const std::string Method::GENERATE_PROFILE_CERT = "generate-profile-cert";
const std::string Method::SIGN_APP = "sign-app";
const std::string Method::SIGN_PROFILE = "sign-profile";
const std::string Method::VERIFY_APP = "verify-app";
const std::string Method::VERIFY_PROFILE = "verify-profile";