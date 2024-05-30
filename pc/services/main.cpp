/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "signature_tools_log.h"
#include "hap_sign_tool.h"
using namespace OHOS::SignatureTools;
int main(int argc, char** argv)
{
    // prepare modes vector by macro DEFINE_MODE which subscribe UPDATER_MAIN_PRE_EVENT event
    std::unique_ptr<HapSignTool> hapSignToolPtr = std::make_unique<HapSignTool>();
    bool isSuccess = hapSignToolPtr->ProcessCmd(argv, argc);
    if (isSuccess) {
        CMD_MSG("Execute command: Success");
        return 0;
    } else {
        CMD_MSG("Execute command: Failed");
        return -1;
    }
    return 0;
}