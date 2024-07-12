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
#ifndef REMOTE_SIGNER_LOG_H
#define REMOTE_SIGNER_LOG_H
#include <stdio.h>
#include <iostream>
#include <time.h>

namespace OHOS {
namespace SignatureTools {

#define REMOTE_LOG(level, fmt, ...) \
    printf("[%s] [%s] [%s] [%d] " fmt "\n", level, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__) \

#ifdef SIGNATURE_LOG_DEBUG
#define REMOTE_SIGNER_LOGI(fmt, ...) REMOTE_LOG("Info", fmt, ##__VA_ARGS__)
#define REMOTE_SIGNER_LOGD(fmt, ...) REMOTE_LOG("Debug", fmt, ##__VA_ARGS__)
#define REMOTE_SIGNER_LOGW(fmt, ...) REMOTE_LOG("Warn", fmt, ##__VA_ARGS__)
#else
#define REMOTE_SIGNER_LOGI(fmt, ...)
#define REMOTE_SIGNER_LOGD(fmt, ...)
#define REMOTE_SIGNER_LOGW(fmt, ...)
#endif

#define REMOTE_SIGNER_LOGF(fmt, ...) REMOTE_LOG("Fatal", fmt, ##__VA_ARGS__)
#define REMOTE_SIGNER_LOGE(fmt, ...) REMOTE_LOG("Error", fmt, ##__VA_ARGS__)

} // namespace SignatureTools
} // namespace OHOS

#endif // REMOTE_SIGNER_LOG_H