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
#ifndef SIGNERTOOLS_SIGNING_BLOCK_H
#define SIGNERTOOLS_SIGNING_BLOCK_H
#include <vector>
namespace OHOS {
    namespace SignatureTools {
        class SigningBlock {
        private:
            int type = 0;
            int length = 0;
            std::vector<signed char> value;
            int offset = 0;
            /**
         * Init Signing Block type and value
         *
         * @param type signing type
         * @param value signing value
         */
        public:
            SigningBlock(int type, std::vector<signed char>& value); //super();
            /**
         * Init Signing Block type and value
         *
         * @param type signing type
         * @param value signing value
         * @param offset signing block offset
         */
            SigningBlock(int type, std::vector<signed char>& value, int offset); //super();
            virtual int getType();
            virtual int getLength();
            virtual std::vector<signed char> getValue();
            virtual int getOffset();
        };
    }
}
#endif
