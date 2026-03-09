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

import java.io.Console;
import java.util.Arrays;

/**
 * PasswordGuard - Secure password storage with interactive input support
 *
 * @since 2023/11/21
 */
public class PasswordGuard {
    private static final LogUtils LOGGER = new LogUtils(PasswordGuard.class);

    private char[] data;

    /**
     * Constructor
     */
    public PasswordGuard() {
        this.data = null;
    }

    /**
     * Get password data
     *
     * @return password char array
     */
    public char[] get() {
        return data;
    }

    /**
     * Clear password data
     */
    public void clear() {
        if (data != null) {
            Arrays.fill(data, '\0');
            data = null;
        }
    }

    /**
     * Get password from user input with timeout
     *
     * @param prompt prompt message
     * @return true if successful, false otherwise
     */
    public boolean getPasswordFromUser(String prompt) {
        clear();

        Console console = System.console();
        if (console == null) {
            LOGGER.error("Console not available");
            return false;
        }

        char[] password = console.readPassword(prompt);
        if (password == null || password.length == 0) {
            LOGGER.warn("Password input cancelled or empty");
            clear();
            return false;
        }

        data = password;
        return true;
    }
}
