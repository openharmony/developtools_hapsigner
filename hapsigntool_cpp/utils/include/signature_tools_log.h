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
#ifndef SIGNATURETOOLS_SIGNATRUE_TOOLS_LOG_H
#define SIGNATURETOOLS_SIGNATRUE_TOOLS_LOG_H
#include <stdio.h>
#include <iostream>
#include <time.h>

#include "signature_tools_errno.h"

namespace OHOS {
namespace SignatureTools {


#define SIGNATURE_LOG(level, fmt, ...) \
    printf("[%s] [%s] [%s] [%d] " fmt "\n", level, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__) \

#ifdef SIGNATURE_LOG_DEBUG
#define SIGNATURE_TOOLS_LOGI(fmt, ...) SIGNATURE_LOG("Info", fmt, ##__VA_ARGS__)
#define SIGNATURE_TOOLS_LOGD(fmt, ...) SIGNATURE_LOG("Debug", fmt, ##__VA_ARGS__)
#define SIGNATURE_TOOLS_LOGW(fmt, ...) SIGNATURE_LOG("Warn", fmt, ##__VA_ARGS__)
#else
#define SIGNATURE_TOOLS_LOGI(fmt, ...)
#define SIGNATURE_TOOLS_LOGD(fmt, ...)
#define SIGNATURE_TOOLS_LOGW(fmt, ...)
#endif

#define SIGNATURE_TOOLS_LOGF(fmt, ...) SIGNATURE_LOG("Fatal", fmt, ##__VA_ARGS__)
#define SIGNATURE_TOOLS_LOGE(fmt, ...) SIGNATURE_LOG("Error", fmt, ##__VA_ARGS__)


/*
* Function: Print the error code and error message to the terminal.
* Parametric Description: command, code, details
* command: Error code variable name as a string.
* code: Error code.
* details: Error description information.
**/
inline void PrintErrorNumberMsg(const std::string& command, const int code, const std::string& details)
{
    time_t now = time(0);
    if (!now) return;
    char timebuffer[100] = { 0 };
    struct tm* time = localtime(&now);
    if (!time && !strftime(timebuffer, sizeof(timebuffer), "%m-%d %H:%M:%S", time)) return;
    std::cerr << timebuffer << " ERROR - " << command << ", code: "
        << code << ". Details: " << details << std::endl;
}

/*
* Function: Print a prompt to the terminal.
* Parametric Description: message
* message: Prompt Description Information.
**/
inline void PrintMsg(const std::string& message)
{
    time_t now = time(0);
    if (!now) {
        return;
    }
    char timebuffer[100] = { 0 };
    struct tm* time = localtime(&now);
    if (!time && !strftime(timebuffer, sizeof(timebuffer), "%m-%d %H:%M:%S", time)) {
        return;
    }
    std::cout << timebuffer << " INFO  - " << message << std::endl;
}

} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATURETOOLS_SIGNATRUE_TOOLS_LOG_H