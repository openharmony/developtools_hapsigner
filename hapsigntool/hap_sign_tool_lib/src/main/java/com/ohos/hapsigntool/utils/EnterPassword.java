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
import com.ohos.hapsigntool.error.ERROR;
import java.io.Console;
import java.io.File;
import java.security.UnrecoverableKeyException;
import java.util.AbstractMap.SimpleEntry;

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
    private static final String PROMPT_KEY_PWD = "please input KeyPwd:";
    private static final String PROMPT_KEYSTORE_PWD = "please input KeystorePwd:";
    private static final String PROMPT_ISSUER_KEY_PWD = "please input IssuerKeyPwd:";
    private static final String PROMPT_ISSUER_KEYSTORE_PWD = "please input IssuerKeystorePwd:";

    /**
     * Constructor of Method
     */
    private EnterPassword() {
    }

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
            if (exception.getMessage().contains("KEY_PASSWORD_ERROR")) {
                LOGGER.error("Failed to load PrivateKey with empty password. open console input keyPwd");
                Console console = System.console();
                char[] password = console.readPassword(promptMessage);
                params.put(keyRightsKey, password);
            }
        }
    }

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
            if (exception.getMessage().contains("INIT_KEYSTORE_FAILED")) {
                LOGGER.error("Failed to load Keystore with empty password. open console input pwd");
                Console console = System.console();
                char[] password = console.readPassword(promptMessage);
                params.put(keyStorePwdKey, password);
            }
        }
    }

    public static void updateParamForKeyPwd(Options params) {
        SimpleEntry<String, String> keyStoreEntry = new SimpleEntry<>(Options.KEY_STORE_FILE, Options.KEY_STORE_RIGHTS);
        SimpleEntry<String, String> keyAliasEntry = new SimpleEntry<>(Options.KEY_ALIAS, Options.KEY_RIGHTS);
        updateKeyAliasPassword(params, keyStoreEntry, keyAliasEntry, PROMPT_KEY_PWD);
    }

    public static void updateParamForIssuerKeyPwdFromKeystore(Options params) {
        SimpleEntry<String, String> keyStoreEntry = new SimpleEntry<>(Options.KEY_STORE_FILE, Options.KEY_STORE_RIGHTS);
        SimpleEntry<String, String> keyAliasEntry = new SimpleEntry<>(Options.ISSUER_KEY_ALIAS, Options.ISSUER_KEY_RIGHTS);
        updateKeyAliasPassword(params, keyStoreEntry, keyAliasEntry, PROMPT_ISSUER_KEY_PWD);
    }

    public static void updateParamForIssuerKeyPwd(Options params) {
        SimpleEntry<String, String> keyStoreEntry = new SimpleEntry<>(Options.ISSUER_KEY_STORE_FILE, Options.ISSUER_KEY_STORE_RIGHTS);
        SimpleEntry<String, String> keyAliasEntry = new SimpleEntry<>(Options.ISSUER_KEY_ALIAS, Options.ISSUER_KEY_RIGHTS);
        updateKeyAliasPassword(params, keyStoreEntry, keyAliasEntry, PROMPT_ISSUER_KEY_PWD);
    }

    public static void updateParamForKeystorePwd(Options params) {
        updateKeystorePassword(
                params,
                Options.KEY_STORE_FILE,
                Options.KEY_STORE_RIGHTS,
                Options.KEY_ALIAS,
                PROMPT_KEYSTORE_PWD
        );
    }

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