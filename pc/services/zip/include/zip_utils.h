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

#ifndef SIGNERTOOLS_ZIP_UTILS_H
#define SIGNERTOOLS_ZIP_UTILS_H
#include "signature_tools_log.h"
#include "zip_data_input.h"
#include <limits>
#include <memory>

namespace OHOS {
    namespace SignatureTools {
        class ZipUtils {
        private:
            static constexpr int ZIP_CENTRAL_DIR_OFFSET_IN_EOCD = 16;

            static constexpr unsigned long UINT32_MAX_VALUE = 4294967295UL;

        public:
            /**
             * set offset value of Central Directory to End of Central Directory Record.
             *
             * @param eocd buffer of End of Central Directory Record.
             * @param offset offset value of Central Directory.
             */
            static bool SetCentralDirectoryOffset(ByteBuffer& eocd, long  offset);

        private:
            static bool SetUInt32ToBuffer(ByteBuffer& buffer, int offset, long value);
        };
    }
}
#endif
