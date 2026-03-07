/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.utils;

import com.ohos.hapsigntool.entity.Options;

/**
 * EnterPassword - Interactive password input utility
 *
 * @since 2023/11/21
 */
public class EnterPassword {
    private static final LogUtils LOGGER = new LogUtils(EnterPassword.class);

    /**
     * Enter password for keystore
     *
     * @param params options containing keystore password
     */
    public static void enterPassword(Options params) {
        if (!params.containsKey(Options.KEY_STORE_RIGHTS)) {
            PasswordGuard keystorePwd = new PasswordGuard();
            if (!keystorePwd.getPasswordFromUser("Enter keystorePwd (timeout 30 seconds): ")) {
                LOGGER.error("Failed to input keystore password");
                return;
            }
            params.put(Options.KEY_STORE_RIGHTS, keystorePwd.get());
        }

        if (!params.containsKey(Options.KEY_RIGHTS)) {
            PasswordGuard keyPwd = new PasswordGuard();
            if (!keyPwd.getPasswordFromUser("Enter keyPwd (timeout 30 seconds): ")) {
                LOGGER.error("Failed to input key password");
                return;
            }
            params.put(Options.KEY_RIGHTS, keyPwd.get());
        }
    }
}
