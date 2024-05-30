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
#ifndef SIGNERTOOLS_PARAMS_H
#define SIGNERTOOLS_PARAMS_H
#include <string>
#include <variant>
#include <iostream>
#include <memory>
#include "options.h"
namespace OHOS {
    namespace SignatureTools {
        struct VariantToString {
            std::string operator()(int value)
            {
                return std::to_string(value);
            }
            std::string operator()(bool value)
            {
                return value ? "true" : "false";
            }
            std::string operator()(const std::string& value)
            {
                return value;
            }
            std::string operator()(char* value)
            {
                return std::string(value);
            }
        };
        /**
         * Params.
         *
         * @since 2021/12/28
         */
        class Params {
            /**
             * Method names in the command line.
             */
        private:
            std::string method;
            /**
         * Hashmap for storing parameters.
         */
            std::shared_ptr<Options> options = std::make_shared<Options>();
            /**
         * Constructor of Params.
         */
        public:
            virtual ~Params()
            {
            }
            Params()
            {
            }
            virtual std::string GetMethod();
            virtual void SetMethod(const std::string& method);
            virtual Options* GetOptions();
            virtual std::string ToString();
        };
        using ParamsSharedPtr = std::shared_ptr<Params>;
    } // namespace SignatureTools
} // namespace OHOS
#endif
