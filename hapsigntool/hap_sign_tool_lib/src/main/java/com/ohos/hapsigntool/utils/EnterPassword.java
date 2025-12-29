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
            LOGGER.error("Console not available. Please run in a terminal environment.");
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
     * Enter the password of parameter.
     * 
     * @param params The options object containing various parameters.
     * @param parameter The parameter used to check whether input is required.
     * @param parameterPwd The parameter used to enter the password of the keystore or key alias.
     * @param promptMessage The prompt message to display to the user.
     */
    private static void enterPasswordOfParameter(
            Options params,
            String parameter,
            String parameterPwd,
            String promptMessage) {
        String checkParam = params.getString(parameter);
        if (StringUtils.isEmpty(checkParam)) {
            return;
        }
        char[] password = readPasswordWithTimeout(promptMessage);
        params.put(parameterPwd, password);
    }

    /**
     * Enter the password of key alias.
     * 
     * @param params The options object containing various parameters.
     */
    public static void enterPasswordOfKeyAlias(Options params) {
        enterPasswordOfParameter(params, Options.KEY_ALIAS, Options.KEY_RIGHTS, PROMPT_KEY_PWD);
    }

    /**
     * Enter the password of issuer key alias.
     * 
     * @param params The options object containing various parameters.
     */
    public static void enterPasswordOfIssuerKeyAlias(Options params) {
        enterPasswordOfParameter(params, Options.ISSUER_KEY_ALIAS, Options.ISSUER_KEY_RIGHTS, PROMPT_ISSUER_KEY_PWD);
    }

    /**
     * Enter the password of keystore.
     * 
     * @param params The options object containing various parameters.
     */
    public static void enterPasswordOfKeystore(Options params) {
        enterPasswordOfParameter(params, Options.KEY_STORE_FILE, Options.KEY_STORE_RIGHTS, PROMPT_KEYSTORE_PWD);
    }

    /**
     * Enter the password of issuer keystore.
     * 
     * @param params The options object containing various parameters.
     */
    public static void enterPasswordOfIssuerKeystore(Options params) {
        enterPasswordOfParameter(params, Options.ISSUER_KEY_STORE_FILE,
                Options.ISSUER_KEY_STORE_RIGHTS, PROMPT_ISSUER_KEYSTORE_PWD);
    }

    /**
     * Enter the password parameters.
     * 
     * @param params The options object containing various parameters.
     */
    public static void enterPassword(Options params) {
        EnterPassword.enterPasswordOfKeystore(params);
        EnterPassword.enterPasswordOfKeyAlias(params);
    }

    /**
     * Enter the password parameters of issuer.
     * 
     * @param params The options object containing various parameters.
     */
    public static void enterPasswordOfIssuer(Options params) {
        EnterPassword.enterPasswordOfIssuerKeystore(params);
        EnterPassword.enterPasswordOfIssuerKeyAlias(params);
    }
}