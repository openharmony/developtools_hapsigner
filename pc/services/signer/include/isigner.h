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
#ifndef SINATURETOOLS_ISINGER_H
#define SINATURETOOLS_ISINGER_H
#include <string>
#include "openssl/x509.h"
namespace OHOS {
    namespace SignatureTools {
        /**
         * ISigner.
         *
         */
         //ISigner通过Get获取到的证书链 密钥对 吊销列表内存由ISigner管理 获取后可直接使用 但不可修改或删除ISigner中的原始内容
        class PKCS7Data;
        class ISigner {
            /**
            * GetKeyPair
             * GetCrls.
             *
             * @return crls
             */
        public:
            virtual STACK_OF(X509_CRL)* GetCrls()const = 0;
            virtual STACK_OF(X509)* GetCertificates()const = 0;
            virtual ~ISigner();
            virtual std::string GetSignature(const std::string& data, const std::string& signAlg)const = 0;
        };
    }
}
#endif