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

package com.ohos.hapsigntool.entity;

import com.ohos.hapsigntool.error.ParamException;

/**
 * SignAppParameters.
 *
 * @since 2024/04/06
 */
public class SignAppParameters implements Parameters {
    /**
     * signature mode, required fields, including localSign/remoteSign
     */
    private Mode mode;

    /**
     * key alias, required fields
     */
    private String keyAlias;

    /**
     * key password, optional fields on localSign mode
     */
    private char[] keyPwd;

    /**
     * application signature certificate file, required fields on localSign mode, optional fields on remoteSign mode
     */
    private String appCertFile;

    /**
     * signed Provision Profile file, p7b format, required fields
     */
    private String profileFile;

    /**
     * indicates whether the profile file has a signature.The options are as follows: SIGNED, UNSIGNED; default :SIGNED
     */
    private ProFileSigned profileSigned = ProFileSigned.SIGNED;

    /**
     * input original application package file, required fields
     */
    private String inFile;

    /**
     * signature algorithm, required fields
     */
    private String signAlg;

    /**
     * keystore file, if signature mode is localSign, required fields on localSign mode, JKS or P12 format
     */
    private String keyStoreFile;

    /**
     * keystore password, optional fields on localSign mode
     */
    private char[] keystorePwd;

    /**
     * output the signed Provision Profile file, required fields
     */
    private String outFile;

    /**
     * user account for online authentication, required fields on remoteSign mode with account auth mode
     */
    private String userName;

    /**
     * user password for online authentication, required fields on remoteSign mode with account auth mode
     */
    private String userPwd;

    /**
     * remote sign service url, required fields on remoteSign mode
     */
    private String signServer;

    /**
     * remote signer plug-in component, required fields on remoteSign mode
     */
    private String signerPlugin;

    /**
     * module.json file path, optional fields
     */
    private String moduleFile;

    /**
     * self sign mode flag. The value 1 means enable self sign, and value 0 means disable. The default value is 0.
     */
    private String selfSign = "0";

    /**
     * remote sign auth mode, required fields on remoteSign mode, including account
     */
    private String onlineAuthMode;

    @Override
    public Options toOptions() throws ParamException {
        Options options = new Options();
        if (mode == null) {
            throw new ParamException(Options.MODE);
        }
        options.put(Options.MODE, mode.getValue());

        if (keyAlias == null) {
            throw new ParamException(Options.KEY_ALIAS);
        }
        options.put(Options.KEY_ALIAS, keyAlias);

        if (keyPwd != null) {
            options.put(Options.KEY_RIGHTS, keyPwd);
        }

        if (profileFile == null) {
            throw new ParamException(Options.PROFILE_FILE);
        }
        options.put(Options.PROFILE_FILE, profileFile);

        if (profileSigned != null) {
            options.put(Options.PROFILE_SIGNED, profileSigned.getValue());
        }

        if (inFile == null) {
            throw new ParamException(Options.IN_FILE);
        }
        options.put(Options.IN_FILE, inFile);

        if (signAlg == null) {
            throw new ParamException(Options.SIGN_ALG);
        }
        options.put(Options.SIGN_ALG, signAlg);

        if (keystorePwd != null) {
            options.put(Options.KEY_STORE_RIGHTS, keystorePwd);
        }

        if (outFile == null) {
            throw new ParamException(Options.OUT_FILE);
        }
        options.put(Options.OUT_FILE, outFile);

        if (moduleFile != null) {
            options.put("moduleFile", moduleFile);
        }

        if (selfSign != null) {
            options.put("selfSign", selfSign);
        }

        keyStoreFileToOptions(options);
        appCertFileToOptions(options);
        remoteSignParamToOptions(options);
        return options;
    }

    private void keyStoreFileToOptions(Options options) throws ParamException {
        if (mode == Mode.LOCAL_SIGN) {
            if (keyStoreFile == null) {
                throw new ParamException(Options.KEY_STORE_FILE);
            }
            options.put(Options.KEY_STORE_FILE, keyStoreFile);
        } else {
            if (keyStoreFile != null) {
                throw new ParamException(Options.KEY_STORE_FILE, "remote sign do not use this param");
            }
        }
    }

    private void appCertFileToOptions(Options options) throws ParamException {
        if (mode == Mode.LOCAL_SIGN) {
            if (appCertFile == null) {
                throw new ParamException(Options.APP_CERT_FILE);
            }
            options.put(Options.APP_CERT_FILE, appCertFile);
        } else {
            if (appCertFile != null) {
                options.put(Options.APP_CERT_FILE, appCertFile);
            }
        }
    }

    private void remoteSignParamToOptions(Options options) throws ParamException {
        if (mode == Mode.LOCAL_SIGN) {
            return;
        }
        if (signServer == null) {
            throw new ParamException("signServer");
        }
        if (userPwd == null) {
            throw new ParamException("userPwd");
        }
        if (userName == null) {
            throw new ParamException("username");
        }
        if (signerPlugin == null) {
            throw new ParamException("signerPlugin");
        }
        if (onlineAuthMode == null) {
            throw new ParamException("onlineAuthMode");
        }
        options.put("signServer", signServer);
        options.put("userPwd", userPwd);
        options.put("username", userName);
        options.put("signerPlugin", signerPlugin);
        options.put("onlineAuthMode", onlineAuthMode);
    }

    public Mode getMode() {
        return mode;
    }

    public void setMode(Mode mode) {
        this.mode = mode;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public char[] getKeyPwd() {
        return keyPwd;
    }

    public void setKeyPwd(char[] keyPwd) {
        this.keyPwd = keyPwd;
    }

    public String getAppCertFile() {
        return appCertFile;
    }

    public void setAppCertFile(String appCertFile) {
        this.appCertFile = appCertFile;
    }

    public String getProfileFile() {
        return profileFile;
    }

    public void setProfileFile(String profileFile) {
        this.profileFile = profileFile;
    }

    public ProFileSigned getProfileSigned() {
        return profileSigned;
    }

    public void setProfileSigned(ProFileSigned profileSigned) {
        this.profileSigned = profileSigned;
    }

    public String getInFile() {
        return inFile;
    }

    public void setInFile(String inFile) {
        this.inFile = inFile;
    }

    public String getSignAlg() {
        return signAlg;
    }

    public void setSignAlg(String signAlg) {
        this.signAlg = signAlg;
    }

    public String getKeyStoreFile() {
        return keyStoreFile;
    }

    public void setKeyStoreFile(String keyStoreFile) {
        this.keyStoreFile = keyStoreFile;
    }

    public char[] getKeystorePwd() {
        return keystorePwd;
    }

    public void setKeystorePwd(char[] keystorePwd) {
        this.keystorePwd = keystorePwd;
    }

    public String getOutFile() {
        return outFile;
    }

    public void setOutFile(String outFile) {
        this.outFile = outFile;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getUserPwd() {
        return userPwd;
    }

    public void setUserPwd(String userPwd) {
        this.userPwd = userPwd;
    }

    public String getSignServer() {
        return signServer;
    }

    public void setSignServer(String signServer) {
        this.signServer = signServer;
    }

    public String getSignerPlugin() {
        return signerPlugin;
    }

    public void setSignerPlugin(String signerPlugin) {
        this.signerPlugin = signerPlugin;
    }

    public String getModuleFile() {
        return moduleFile;
    }

    public void setModuleFile(String moduleFile) {
        this.moduleFile = moduleFile;
    }

    public String getSelfSign() {
        return selfSign;
    }

    public void setSelfSign(String selfSign) {
        this.selfSign = selfSign;
    }

    public String getOnlineAuthMode() {
        return onlineAuthMode;
    }

    public void setOnlineAuthMode(String onlineAuthMode) {
        this.onlineAuthMode = onlineAuthMode;
    }
}
