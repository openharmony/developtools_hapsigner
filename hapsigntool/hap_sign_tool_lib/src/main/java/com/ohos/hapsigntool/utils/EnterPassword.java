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
import com.ohos.hapsigntool.error.CustomException;
import java.io.Console;
import java.io.File;
import java.util.AbstractMap.SimpleEntry;
import java.util.Scanner;

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
            return null;
        }

        final char[][] password = {null};
        Scanner scanner = new Scanner(System.in);
        Thread readPasswordThread = new Thread(() -> {
            System.out.print(promptMessage);
            password[0] = scanner.nextLine().toCharArray();
        });

        readPasswordThread.start();

        try {
            readPasswordThread.join(MAX_WAIT_TIME);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        if (password[0] == null) {
            readPasswordThread.interrupt();
            System.out.println();
            LOGGER.error("No password input, closing input.");
            console.flush();
        }

        return password[0];
    }

    /**
     * Updates the password for a key alias.
     * 
     * @param params The options object containing various parameters.
     * @param keyStoreEntry A SimpleEntry containing the key for the keystore file and its password.
     * @param keyAliasEntry A SimpleEntry containing the key for the key alias and its rights.
     * @param promptMessage The prompt message to display to the user.
     */
    private static void updateKeyAliasPassword(
            Options params,
            SimpleEntry<String, String> keyStoreEntry,
            SimpleEntry<String, String> keyAliasEntry,
            String promptMessage) {

        String keyStoreFileKey = keyStoreEntry.getKey();
        String keyStorePwdKey = keyStoreEntry.getValue();
        String keyAliasKey = keyAliasEntry.getKey();
        String keyRightsKey = keyAliasEntry.getValue();
        Object keyStorePwd = params.get(keyStorePwdKey);
        Object keyPwd = params.get(keyRightsKey);

        if (keyPwd != null) {
            return;
        }
        String keyStoreFile = params.getString(keyStoreFileKey, "");
        if (StringUtils.isEmpty(keyStoreFile)) {
            return;
        }
        File keyStore = new File(keyStoreFile);
        if (!keyStore.exists()) {
            return;
        }
        String alias = params.getString(keyAliasKey);
        if (StringUtils.isEmpty(alias)) {
            return;
        }
        try {
            KeyStoreHelper tempKeyStoreHelper = new KeyStoreHelper(keyStoreFile, (char[]) keyStorePwd);
            tempKeyStoreHelper.loadPrivateKey(alias, new char[0]);
        } catch (CustomException exception) {
            if (exception.getMessage().contains("password error")) {
                LOGGER.error("Failed to load PrivateKey with empty password. open console input keyPwd");
                char[] password = readPasswordWithTimeout(promptMessage);
                params.put(keyRightsKey, password);
            }
        }
    }

    /**
     * Updates the keystore password.
     * 
     * @param params The options object containing various parameters.
     * @param keyStoreFileKey The key for the keystore file path.
     * @param keyStorePwdKey The key for the keystore password.
     * @param keyAliasKey The key for the key alias.
     * @param promptMessage The prompt message to display to the user.
     */
    private static void updateKeystorePassword(
            Options params,
            String keyStoreFileKey,
            String keyStorePwdKey,
            String keyAliasKey,
            String promptMessage) {

        Object keyStorePwd = params.get(keyStorePwdKey);
        if (keyStorePwd != null) {
            return;
        }
        String keyStoreFile = params.getString(keyStoreFileKey, "");
        if (StringUtils.isEmpty(keyStoreFile)) {
            return;
        }
        File keyStore = new File(keyStoreFile);
        if (!keyStore.exists()) {
            return;
        }
        String alias = params.getString(keyAliasKey);
        if (StringUtils.isEmpty(alias)) {
            return;
        }
        try {
            new KeyStoreHelper(keyStoreFile, new char[0]);
        } catch (CustomException exception) {
            if (exception.getMessage().contains("Init keystore failed")) {
                LOGGER.error("Failed to load Keystore with empty password. open console input pwd");
                char[] password = readPasswordWithTimeout(promptMessage);
                params.put(keyStorePwdKey, password);
            }
        }
    }

    /**
     * Updates the password parameters for key alias.
     * 
     * @param params The options object containing various parameters.
     */
    public static void updateParamForKeyPwd(Options params) {
        SimpleEntry<String, String> keyStoreEntry = new SimpleEntry<>(Options.KEY_STORE_FILE,
                                                                      Options.KEY_STORE_RIGHTS);
        SimpleEntry<String, String> keyAliasEntry = new SimpleEntry<>(Options.KEY_ALIAS,
                                                                      Options.KEY_RIGHTS);
        updateKeyAliasPassword(params, keyStoreEntry, keyAliasEntry, PROMPT_KEY_PWD);
    }

    /**
     * Updates the password parameters for issuer key alias from keystore.
     * 
     * @param params The options object containing various parameters.
     */
    public static void updateParamForIssuerKeyPwdFromKeystore(Options params) {
        SimpleEntry<String, String> keyStoreEntry = new SimpleEntry<>(Options.KEY_STORE_FILE,
                                                                      Options.KEY_STORE_RIGHTS);
        SimpleEntry<String, String> keyAliasEntry = new SimpleEntry<>(Options.ISSUER_KEY_ALIAS,
                                                                      Options.ISSUER_KEY_RIGHTS);
        updateKeyAliasPassword(params, keyStoreEntry, keyAliasEntry, PROMPT_ISSUER_KEY_PWD);
    }

    /**
     * Updates the password parameters for issuer key alias from issuer keystore.
     * 
     * @param params The options object containing various parameters.
     */
    public static void updateParamForIssuerKeyPwd(Options params) {
        SimpleEntry<String, String> keyStoreEntry = new SimpleEntry<>(Options.ISSUER_KEY_STORE_FILE,
                                                                      Options.ISSUER_KEY_STORE_RIGHTS);
        SimpleEntry<String, String> keyAliasEntry = new SimpleEntry<>(Options.ISSUER_KEY_ALIAS,
                                                                      Options.ISSUER_KEY_RIGHTS);
        updateKeyAliasPassword(params, keyStoreEntry, keyAliasEntry, PROMPT_ISSUER_KEY_PWD);
    }

    /**
     * Updates the password parameters for keystore.
     * 
     * @param params The options object containing various parameters.
     */
    public static void updateParamForKeystorePwd(Options params) {
        updateKeystorePassword(
                params,
                Options.KEY_STORE_FILE,
                Options.KEY_STORE_RIGHTS,
                Options.KEY_ALIAS,
                PROMPT_KEYSTORE_PWD
        );
    }

    /**
     * Updates the password parameters for issuer keystore.
     * 
     * @param params The options object containing various parameters.
     */
    public static void updateParamForIssuerKeystorePwd(Options params) {
        updateKeystorePassword(
                params,
                Options.ISSUER_KEY_STORE_FILE,
                Options.ISSUER_KEY_STORE_RIGHTS,
                Options.ISSUER_KEY_ALIAS,
                PROMPT_ISSUER_KEYSTORE_PWD
        );
    }

    public static void updateParamForPassword(Options params) {
        EnterPassword.updateParamForKeystorePwd(params);
        EnterPassword.updateParamForKeyPwd(params);
    }

    public static void updateParamForIssuerPwd(Options params) {
        if (!params.containsKey(Options.ISSUER_KEY_STORE_FILE)) {
            EnterPassword.updateParamForIssuerKeyPwdFromKeystore(params);
        } else {
            EnterPassword.updateParamForIssuerKeystorePwd(params);
            EnterPassword.updateParamForIssuerKeyPwd(params);
        }
    }
}