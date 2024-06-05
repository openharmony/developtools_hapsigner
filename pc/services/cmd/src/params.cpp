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
#include "params.h"
using namespace OHOS::SignatureTools;
std::string Params::GetMethod()
{
    return method;
}
void Params::SetMethod(const std::string& method)
{
    this->method = method;
}
Options* Params::GetOptions()
{
    return options.get();
}
std::string Params::ToString()
{
    std::string destStr;
    destStr.append("Params{ method: ");
    destStr.append(method);
    destStr.append(", params: ");
    for (const auto& item : *GetOptions()) {
        destStr.append("-");
        destStr.append(item.first);
        destStr.append("=");
        destStr.append(std::visit(VariantToString{}, item.second));
        destStr.append(";");
    }
    destStr.append("}");
    return destStr;
}