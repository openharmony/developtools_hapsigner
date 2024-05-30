/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SIGNERTOOLS_CONSTANT_H
#define SIGNERTOOLS_CONSTANT_H

#include <stdint.h>
#include <string>

namespace OHOS {
    namespace SignatureTools {
        const char APP_SIGNING_CAPABILITY[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x0A, 0x01, 0x00 };
        const char PROFILE_SIGNING_CAPABILITY[] = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x0A, 0x01, 0x01 };
        const long DEFAULT_VALIDITY = 31536000;
        const long DEFAULT_START_VALIDITY = 0;
        const long DEFAULT_TIME = 86400;
        const long DEFAULT_CERT_VERSION = 2;
        const long DEFAULT_CERT_SERIALNUM = 1;
        const std::string SIGN_ALG_SHA256 = "SHA256withECDSA";
        const std::string DEFAULT_BASIC_EXTENSION = "critical,CA:FALSE";
        const std::string DEFAULT_KEYUSAGE_EXTENSION = "digitalSignature";
        const std::string DEFAULT_EXTEND_KEYUSAGE = "codeSigning";
        const std::string NID_BASIC_CONST = "basicConstraints";
        const std::string NID_KEYUSAGE_CONST = "keyUsage";
        const std::string NID_EXT_KEYUSAGE_CONST = "extendedKeyUsage";       
        const std::string HELP_FILE_PATH = "./help.txt";

#if  0
        //下面是模板
        constexpr int32_t ONE_DAY_HOUR = 24;
        static const std::string DUPDATE_ENGINE_CONFIG_PATH = "/system/etc/update/dupdate_config.json";

        enum class CommonEventType {
            AUTO_UPGRADE = 0,
            NET_CHANGED,
            TIME_CHANGED,
            TIME_ZONE_CHANGED,
            BOOT_COMPLETE,
            PROCESS_INIT,
            NIGHT_UPGRADE,
            SCREEN_OFF,
            UPGRADE_REMIND,
        };
#else
        constexpr int32_t ONE_DAY_HOUR = 24;
        constexpr int32_t ONE_DAY_MINUTE = 60;
        constexpr int32_t ONE_DAY_SECOND = 60;

        enum class AlgorithmLength {
            NIST_P_256 = 256,
            NIST_P_384 = 384,
        };

#endif
    } // namespace UpdateEngine
} // namespace OHOS
#endif // CONSTANT_H