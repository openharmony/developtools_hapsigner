/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
import java.io.Console;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Provider function of enter password.
 * 
 * @since 2025/12/19
 */
public class EnterPassword {
    /**
     * Add log info.
     */
    private static final LogUtils LOGGER = new LogUtils(EnterPassword.class);
    private static final String PROMPT_KEY_PWD = "please input KeyPwd (timeout 30 seconds):";
    private static final String PROMPT_KEYSTORE_PWD = "please input KeystorePwd (timeout 30 seconds):";
    private static final String PROMPT_ISSUER_KEY_PWD = "please input IssuerKeyPwd (timeout 30 seconds):";
    private static final String PROMPT_ISSUER_KEYSTORE_PWD = "please input IssuerKeystorePwd (timeout 30 seconds):";
    private static final int MAX_WAIT_TIME = 30000;

    /**
     * Constructor of Method
     */
    private EnterPassword() {
    }

    /**
     * Reads a password with a specified timeout. If no input is received within the timeout, the input is closed.
     * 
     * @param promptMessage The prompt message to display to the user.
     * @return The password entered by the user, or null if not input is received.
     */
    private static char[] readPasswordWithTimeout(String promptMessage) {
        Console console = System.console();
        if (console == null) {
            System.err.println("Console not available. Please run in a terminal environment.");
            return new char[0];
        }

        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                1,
                1,
                0L,
                TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>()
        );
        Future<char[]> future = executor.submit(() -> {
            System.out.print(promptMessage);
            return console.readPassword();
        });

        try {
            return future.get(MAX_WAIT_TIME, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            System.out.println();
            LOGGER.error("No password input, closing input.");
            return new char[0];
        } catch (InterruptedException | ExecutionException e) {
            return new char[0];
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * Updates the keystore password.
     * 
     * @param params The options object containing various parameters.
     * @param key The parameter used to check whether input is required.
     * @param pwd The password used to enter the password of the keystore or key alias.
     * @param promptMessage The prompt message to display to the user.
     */
    private static void updateParamForKey(
            Options params,
            String key,
            String pwd,
            String promptMessage) {

        String checkParam = params.getString(key);
        if (StringUtils.isEmpty(checkParam)) {
            return;
        }
        char[] password = readPasswordWithTimeout(promptMessage);
        params.put(pwd, password);
    }

    /**
     * Updates the password parameters for key alias.
     * 
     * @param params The options object containing various parameters.
     */
    public static void updateParamForKeyPwd(Options params) {
        updateParamForKey(params, Options.KEY_ALIAS, Options.KEY_RIGHTS, PROMPT_KEY_PWD);
    }

    /**
     * Updates the password parameters for issuer key alias from issuer keystore.
     * 
     * @param params The options object containing various parameters.
     */
    public static void updateParamForIssuerKeyPwd(Options params) {
        updateParamForKey(params, Options.ISSUER_KEY_ALIAS, Options.ISSUER_KEY_RIGHTS, PROMPT_ISSUER_KEY_PWD);
    }

    /**
     * Updates the password parameters for keystore.
     * 
     * @param params The options object containing various parameters.
     */
    public static void updateParamForKeystorePwd(Options params) {
        updateParamForKey(params, Options.KEY_STORE_FILE, Options.KEY_STORE_RIGHTS, PROMPT_KEYSTORE_PWD);
    }

    /**
     * Updates the password parameters for issuer keystore.
     * 
     * @param params The options object containing various parameters.
     */
    public static void updateParamForIssuerKeystorePwd(Options params) {
        updateParamForKey(params, Options.ISSUER_KEY_STORE_FILE,
                Options.ISSUER_KEY_STORE_RIGHTS, PROMPT_ISSUER_KEYSTORE_PWD);
    }

    public static void updateParamForPassword(Options params) {
        EnterPassword.updateParamForKeystorePwd(params);
        EnterPassword.updateParamForKeyPwd(params);
    }

    public static void updateParamForIssuerPwd(Options params) {
        EnterPassword.updateParamForIssuerKeystorePwd(params);
        EnterPassword.updateParamForIssuerKeyPwd(params);
    }
}