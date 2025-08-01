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

#include "dynamic_lib_handle.h"

namespace OHOS {
namespace SignatureTools {
namespace DynamicLibHandle {
void* g_handle = nullptr;

void FreeHandle()
{
    if (g_handle != nullptr) {
        if (dlclose(g_handle) != 0) {
            SIGNATURE_TOOLS_LOGE("dlclose() %s", dlerror());
            return;
        }
        g_handle = nullptr;
    }
}
} // DynamicLibHandle
} // namespace SignatureTools
} // namespace OHOS